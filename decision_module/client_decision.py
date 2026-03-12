from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class DecisionResult:
    """Client-side decision output."""

    z_plain: float
    prob: float
    is_anomaly: bool
    decrypted: bool


class ClientDecision:
    """
    Client-side decryption and anomaly decision.

    Responsibilities:
    - If the server returned a ciphertext (HE route), decrypt it using the
      client's private key (held by the encryptor).
    - Apply sigmoid activation to the logit z.
    - Compare probability against threshold to produce an anomaly flag.

    The server must NEVER decrypt — decryption only happens here.
    """

    def __init__(self, encryptor: Any, threshold: float = 0.5) -> None:
        if encryptor is None:
            raise ValueError("ClientDecision requires a real encryptor (client holds the private key).")
        self.encryptor = encryptor
        self.threshold = float(threshold)

    def decrypt_if_needed(
        self,
        z: Any,
        payload: Dict[str, Dict[str, Any]],
        enable_he: bool,
    ) -> tuple[float, bool]:
        """
        Decrypt z if the HE route produced encrypted fields.

        Returns (z_plain, was_decrypted).
        """
        if enable_he and payload.get("encrypted"):
            return float(self.encryptor.decrypt(z)), True
        return float(z), False

    @staticmethod
    def sigmoid(z: float) -> float:
        """Numerically safe sigmoid."""
        z_clamped = max(min(z, 20.0), -20.0)
        try:
            return 1.0 / (1.0 + math.exp(-z_clamped))
        except OverflowError:
            return 0.0 if z < 0 else 1.0

    def decide(
        self,
        z: Any,
        payload: Dict[str, Dict[str, Any]],
        enable_he: bool,
    ) -> DecisionResult:
        """
        Full client-side decision pipeline:
        decrypt (if needed) -> sigmoid -> threshold comparison.
        """
        z_plain, decrypted = self.decrypt_if_needed(z, payload, enable_he)
        prob = self.sigmoid(z_plain)
        is_anomaly = prob > self.threshold

        return DecisionResult(
            z_plain=z_plain,
            prob=prob,
            is_anomaly=is_anomaly,
            decrypted=decrypted,
        )
