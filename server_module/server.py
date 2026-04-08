from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib

from logistic_regression_model.inference.inference_tools import (
    FEATURE_COLS,
    resolve_model_path,
)

# Mapping from sklearn feature column names to internal field names.
COLUMN_TO_INTERNAL: Dict[str, str] = {
    "User ID": "user_id",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
}


class TrainedModelServer:
    """
    Server-side LR inference using weights extracted from a trained sklearn model.

    Implements ``ModelServerLike`` protocol (adaptive_routing.interfaces).

    Supports:
    - plaintext-only payloads  → returns ``float`` z
    - mixed payloads with CKKS-encrypted values → returns ciphertext z_enc

    The server must NOT decrypt — decryption is the client's responsibility.
    """

    def __init__(
        self,
        model_path: Path | None = None,
        feature_map: Dict[str, str] | None = None,
    ) -> None:
        model_path = model_path or resolve_model_path()
        feature_map = feature_map or COLUMN_TO_INTERNAL

        model = joblib.load(model_path)
        coefs = model.coef_[0]
        intercept = float(model.intercept_[0])

        # Build weights dict keyed by internal field names.
        self.weights: Dict[str, float] = {}
        for i, col_name in enumerate(FEATURE_COLS):
            internal_name = feature_map.get(col_name, col_name)
            self.weights[internal_name] = float(coefs[i])
        self.bias: float = intercept

    @classmethod
    def from_weights(
        cls,
        weights: Dict[str, float],
        bias: float = 0.0,
    ) -> TrainedModelServer:
        """Create an instance with explicit weights (useful for testing)."""
        instance = object.__new__(cls)
        instance.weights = dict(weights)
        instance.bias = float(bias)
        return instance

    def infer(self, payload: Dict[str, Dict[str, Any]]) -> Any:
        """
        Compute z = bias + sum(w_k * x_k) over plain and encrypted fields.

        Fields not present in ``self.weights`` are assigned weight 0
        (they are encrypted for privacy but do not contribute to inference).
        """
        z_plain = float(self.bias)
        z_enc: Any = None

        # Plaintext part
        for k, v in payload.get("plain", {}).items():
            w = float(self.weights.get(k, 0.0))
            try:
                z_plain += w * float(v)
            except Exception:
                continue

        # Encrypted part (CKKS supports scalar mul & add)
        for k, enc_v in payload.get("encrypted", {}).items():
            w = float(self.weights.get(k, 0.0))
            term = enc_v * w
            z_enc = term if z_enc is None else (z_enc + term)

        # Fold plaintext constant into ciphertext if any encrypted terms exist
        if z_enc is not None:
            return z_enc + z_plain

        return z_plain
