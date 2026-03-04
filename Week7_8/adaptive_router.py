from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Tuple

from Week2.sensitivity_classifier.classifier import SensitivityClassifier
from Week6.mixed_protection import MixedProtectionPipeline
from Week7_8.feature_encoder import SimpleRecordEncoder
from Week7_8.interfaces import ModelServerLike, RecordEncoder, SensitivityClassifierLike


RouteName = Literal["server_plain", "server_mixed_he"]


@dataclass
class RoutingConfig:
    """
    Adaptive routing policy knobs (PoC-friendly).
    """

    # If sensitivity is HIGH, we must use HE.
    # If sensitivity is MEDIUM, we can adapt based on latency budget.
    latency_budget_ms: float = 120.0

    # Simulated network RTT to the server (round-trip), for demo/plots.
    network_rtt_ms: float = 30.0

    # Default processing-time priors (before EMA has any signal).
    plain_default_ms: float = 10.0
    he_default_ms: float = 80.0

    # If True, treat MEDIUM as "should prefer HE unless too slow".
    prefer_he_on_medium: bool = True

    # ----- Multi-objective routing knobs -----
    # If True, MEDIUM-level traffic uses a simple utility model that
    # trades off privacy gain vs. latency cost instead of a hard
    # "prefer HE if under budget" rule.
    enable_multi_objective: bool = True

    # Utility is roughly:
    #   U(route) = privacy_weight * privacy_gain(route, record)
    #              - latency_weight * estimated_latency_ms(route)
    # For plaintext we typically treat privacy_gain ~= 0.
    privacy_weight: float = 1.0
    # Because latency is in ms, this is a small number to keep the
    # scales comparable to privacy_weight.
    latency_weight: float = 0.01


class ServerLRStub:
    """
    Server-side LR inference stub that supports:
    - plaintext-only payloads (returns float z)
    - mixed payloads with Paillier-encrypted values (returns ciphertext z_enc)

    Notes:
    - The server must NOT decrypt.
    - The client will decrypt and apply threshold.
    """

    def __init__(self, weights: Dict[str, float] | None = None, bias: float = 0.0) -> None:
        # PoC weights across fields we currently encode.
        self.weights = weights or {
            "session_duration": 0.003,
            "failed_attempts": 0.60,
            "behavioral_score": -0.04,
            # encoded-but-sensitive fields (keep small weights for stability)
            "user_id": 0.0002,
            "ip_address": 0.02,
            "location": 0.0001,
            "timestamp": 0.01,
            "device_type": 0.0001,
            "login_status": 0.0001,
        }
        self.bias = bias

    def infer(self, payload: Dict[str, Dict[str, Any]]) -> Any:
        z_plain = float(self.bias)
        z_enc: Any = None  # Paillier ciphertext when any encrypted fields exist

        # plaintext part
        for k, v in payload.get("plain", {}).items():
            w = float(self.weights.get(k, 0.0))
            try:
                z_plain += w * float(v)
            except Exception:
                # if something non-numeric leaks in, ignore it in PoC
                continue

        # encrypted part
        for k, enc_v in payload.get("encrypted", {}).items():
            w = float(self.weights.get(k, 0.0))

            # phe.EncryptedNumber supports multiplication by scalar and addition.
            term = enc_v * w
            z_enc = term if z_enc is None else (z_enc + term)

        # if there was any encrypted term, fold plaintext constant into ciphertext
        if z_enc is not None:
            return z_enc + z_plain

        return z_plain


class AdaptiveRouter:
    """
    Week7-8 deliverable: Adaptive routing between plaintext vs mixed-HE paths.

    Data flow:
      raw_record
        -> (Week2) SensitivityClassifier.classify(raw_record)
        -> encode(raw_record) to numeric (so HE is possible)
        -> choose route
        -> protect via Week6 MixedProtectionPipeline (enable_he True/False)
        -> server infer z (plaintext float or ciphertext)
        -> client decrypt (if needed) and sigmoid/threshold decision
    """

    def __init__(
        self,
        config: RoutingConfig | None = None,
        encryptor: Any | None = None,
        sensitivity_clf: SensitivityClassifierLike | None = None,
        encoder: RecordEncoder | None = None,
        pipeline: MixedProtectionPipeline | None = None,
        server: ModelServerLike | None = None,
        threshold: float = 0.5,
    ) -> None:
        self.cfg = config or RoutingConfig()
        self.sensitivity_clf = sensitivity_clf or SensitivityClassifier()
        self.encoder = encoder or SimpleRecordEncoder()

        # 在真實系統前提下：必須提供一個真正的 HE encryptor
        if encryptor is None:
            raise ValueError(
                "AdaptiveRouter 需要一個真實的 HE encryptor，"
                "請在建構時傳入，例如 Week6.PaillierEncryptor。"
            )
        self.encryptor = encryptor
        self.pipeline = pipeline or MixedProtectionPipeline(encryptor=self.encryptor)
        self.server = server or ServerLRStub()
        self.threshold = float(threshold)

        # very simple exponential moving average latency tracker
        self._ema_plain_ms: Optional[float] = None
        self._ema_he_ms: Optional[float] = None

    def _ema_update(self, current: float, new: float, alpha: float = 0.3) -> float:
        return new if current is None else (alpha * new + (1 - alpha) * current)

    # --- Privacy utility helpers -------------------------------------------------

    def _privacy_gain_for_he(self, sensitivity: Dict[str, Any]) -> float:
        """
        Very simple privacy "gain" score for choosing HE on this record.

        Intuition:
        - LOW:  ~0      (we almost never route LOW here)
        - MEDIUM: base 1.0 + risk_score in [0, 1]
        - HIGH:   base 2.0 + risk_score (but HIGH is already forced to HE)
        """
        level = str(sensitivity.get("sensitivity_level", "LOW")).upper()
        risk_score = float(sensitivity.get("risk_score", 0.0))

        if level == "HIGH":
            base = 2.0
        elif level == "MEDIUM":
            base = 1.0
        else:
            base = 0.0

        # keep the function monotone in risk_score but bounded
        return max(0.0, base + max(0.0, min(risk_score, 1.0)))

    def _estimate_total_latency_ms(self, route: RouteName) -> float:
        # estimate = (network rtt) + (processing)
        if route == "server_plain":
            processing = self._ema_plain_ms or self.cfg.plain_default_ms
        elif route == "server_mixed_he":
            processing = self._ema_he_ms or self.cfg.he_default_ms
        else:
            processing = self.cfg.plain_default_ms
        return self.cfg.network_rtt_ms + processing

    def decide_route(self, raw_record: Dict[str, Any]) -> Tuple[RouteName, Dict[str, Any]]:
        """
        Returns (route_name, sensitivity_result)
        """
        s = self.sensitivity_clf.classify(raw_record)

        # HIGH: must encrypt (regardless of utility).
        if s.get("encryption_required", False):
            return "server_mixed_he", s

        # LOW: prefer plaintext
        if not s.get("is_sensitive", False):
            return "server_plain", s

        # MEDIUM: adapt
        plain_est = self._estimate_total_latency_ms("server_plain")
        he_est = self._estimate_total_latency_ms("server_mixed_he")

        # If multi-objective mode is enabled, use a utility function that
        # explicitly balances privacy gain against latency.
        if self.cfg.enable_multi_objective:
            privacy_gain_he = self._privacy_gain_for_he(s)

            # Plaintext has ~zero privacy gain, only latency cost.
            u_plain = -self.cfg.latency_weight * plain_est

            # HE route has positive privacy gain but higher latency.
            u_he = (
                self.cfg.privacy_weight * privacy_gain_he
                - self.cfg.latency_weight * he_est
            )

            # Optional: still respect a hard latency budget as a guardrail.
            if he_est > self.cfg.latency_budget_ms and u_he < u_plain:
                return "server_plain", s

            return ("server_mixed_he", s) if u_he >= u_plain else ("server_plain", s)

        # Fallback: original "prefer HE if under budget" heuristic.
        if self.cfg.prefer_he_on_medium and he_est <= self.cfg.latency_budget_ms:
            return "server_mixed_he", s

        # if HE too slow under current estimates, fall back to plaintext
        return "server_plain", s

    def process(self, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        End-to-end routing + inference + client-side decision.
        """
        route, sensitivity = self.decide_route(raw_record)
        enable_he = route == "server_mixed_he"

        # encode to numeric to ensure HE encryptor can run on all sensitive fields
        model_record = self.encoder.encode(raw_record)

        t0 = time.time()
        payload = self.pipeline.protect_record(model_record, enable_he=enable_he)

        # server infer: returns float z or ciphertext z_enc
        z = self.server.infer(payload)

        # client decision: if HE route produced encrypted fields, decrypt z
        z_plain: float
        decrypted = False
        if enable_he and payload.get("encrypted"):
            if self.pipeline.adaptive_module.encryptor is None:
                raise RuntimeError("Route requires HE but no encryptor was provided on the client.")
            z_plain = float(self.pipeline.adaptive_module.encryptor.decrypt(z))
            decrypted = True
        else:
            z_plain = float(z)

        # sigmoid + threshold (with simple numerical guarding)
        # clamp z to avoid extreme exp() overflow in edge cases
        z_clamped = max(min(z_plain, 20.0), -20.0)
        try:
            prob = 1.0 / (1.0 + math.exp(-z_clamped))
        except OverflowError:
            prob = 0.0 if z_plain < 0 else 1.0
        is_anomaly = prob > self.threshold

        elapsed_ms = (time.time() - t0) * 1000.0
        if enable_he:
            self._ema_he_ms = self._ema_update(self._ema_he_ms, elapsed_ms)
        else:
            self._ema_plain_ms = self._ema_update(self._ema_plain_ms, elapsed_ms)

        return {
            "route": route,
            "enable_he": enable_he,
            "sensitivity": sensitivity,
            "payload_summary": {
                "plain_keys": sorted(payload.get("plain", {}).keys()),
                "encrypted_keys": sorted(payload.get("encrypted", {}).keys()),
            },
            "decrypted": decrypted,
            "z": z_plain,
            "prob": prob,
            "is_anomaly": is_anomaly,
            "latency_ms": round(elapsed_ms, 3),
            "latency_est_ms": round(self._estimate_total_latency_ms(route), 3),
        }

