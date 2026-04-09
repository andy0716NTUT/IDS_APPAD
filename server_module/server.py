from __future__ import annotations

import math
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

from logistic_regression_model.inference.inference_tools import (
    FEATURE_COLS,
    load_trained_model,
    resolve_model_path,
)
from logistic_regression_model.inference.logistic_regression_ckks import LogisticRegressionCKKS


# Mapping from sklearn feature column names to internal field names.
COLUMN_TO_INTERNAL: Dict[str, str] = {
    "User ID": "user_id",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
}


def _sigmoid(z: float) -> float:
    z = max(-60.0, min(60.0, z))
    return 1.0 / (1.0 + math.exp(-z))


class LRModelServer:
    """
    Single source-of-truth server for LR model loading + plain/CKKS inference.

    Implements ``ModelServerLike`` protocol (adaptive_routing.interfaces).

    Supports:
    - plaintext inference on internal records
    - CKKS inference on internal records + sensitive fields
    - mixed plain/encrypted payload inference via ``infer(payload)``

    The server must NOT decrypt — decryption is the client's responsibility.
    """

    def __init__(
        self,
        model_path: Path | None = None,
        feature_map: Dict[str, str] | None = None,
        *,
        auto_train_if_missing: bool = False,
    ) -> None:
        model_path = model_path or resolve_model_path()
        feature_map = feature_map or COLUMN_TO_INTERNAL

        if not model_path.exists():
            if auto_train_if_missing:
                self._train_model(model_path)
            else:
                raise FileNotFoundError(
                    f"Model file not found: {model_path}. "
                    "Please run logistic_regression_model/training/train_logistic_regression.py first."
                )

        model = load_trained_model(model_path)
        coefs = model.coef_[0]
        intercept = float(model.intercept_[0])

        self.model_path = model_path
        self.feature_map = dict(feature_map)
        self.model = model

        # Build weights dict keyed by internal field names for router payload infer.
        self.weights: Dict[str, float] = {}
        for i, col_name in enumerate(FEATURE_COLS):
            internal_name = feature_map.get(col_name, col_name)
            self.weights[internal_name] = float(coefs[i])
        self.bias: float = intercept

        # Reuse CKKS inference implementation but force trained model weights.
        self.ckks_model = LogisticRegressionCKKS(
            weights=self.weights,
            bias=self.bias,
        )

    @staticmethod
    def _train_model(model_path: Path) -> None:
        train_script = model_path.parents[1] / "training" / "train_logistic_regression.py"
        if not train_script.exists():
            raise FileNotFoundError(f"Training script not found: {train_script}")

        output_dir = model_path.parent
        cmd = [
            sys.executable,
            str(train_script),
            "--output-dir",
            str(output_dir),
        ]
        completed = subprocess.run(cmd, capture_output=True, text=True)
        if completed.returncode != 0 or not model_path.exists():
            raise RuntimeError(
                "Failed to auto-train LR model. "
                f"stdout={completed.stdout}\nstderr={completed.stderr}"
            )

    @classmethod
    def from_weights(
        cls,
        weights: Dict[str, float],
        bias: float = 0.0,
    ) -> LRModelServer:
        """Create an instance with explicit weights (useful for testing)."""
        instance = object.__new__(cls)
        instance.model_path = None
        instance.feature_map = dict(COLUMN_TO_INTERNAL)
        instance.model = None
        instance.weights = dict(weights)
        instance.bias = float(bias)
        instance.ckks_model = LogisticRegressionCKKS(
            weights=instance.weights,
            bias=instance.bias,
        )
        return instance

    def predict_proba_plain(self, record: Dict[str, Any]) -> float:
        z = float(self.bias)
        for feature, w in self.weights.items():
            value = record.get(feature, 0.0)
            try:
                z += float(w) * float(value)
            except Exception:
                continue
        return max(0.0, min(1.0, _sigmoid(z)))

    def predict_proba_ckks(
        self,
        record: Dict[str, Any],
        sensitive_fields: set[str] | None = None,
    ) -> tuple[float, float, list[str]]:
        return self.ckks_model.predict_proba(record=record, sensitive_fields=sensitive_fields)

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


# Backward-compatible name used by existing pipeline/tests.
TrainedModelServer = LRModelServer
