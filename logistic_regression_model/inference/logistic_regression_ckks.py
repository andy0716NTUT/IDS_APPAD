from __future__ import annotations

import math
from typing import Any

from ckks_homomorphic_encryption import CKKSEncryptor


class LogisticRegressionCKKS:
    """
    CKKS 版 Logistic Regression 推論。

    流程：
    1) 對敏感欄位做 CKKS 加密
    2) 在密文域做線性組合 z = w·x + b（敏感欄位走同態計算）
    3) 在密文域用低階多項式近似 sigmoid
    4) 解密得到機率
    """

    def __init__(
        self,
        encryptor: CKKSEncryptor | None = None,
        weights: dict[str, float] | None = None,
        bias: float | None = None,
    ) -> None:
        self.encryptor = encryptor or CKKSEncryptor()
        self.weights = weights or {
            "session_duration": 0.003,
            "failed_attempts": 0.6,
            "behavioral_score": -0.04,
        }
        self.bias = -1.5 if bias is None else float(bias)

    @staticmethod
    def _sigmoid_plain(z: float) -> float:
        z = max(-60.0, min(60.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def _sigmoid_poly_encrypted(self, z_enc):
        # 3rd-order approximation around 0: sigmoid(x) ≈ 0.5 + 0.197x - 0.004x^3
        z2 = z_enc * z_enc
        z3 = z2 * z_enc
        return (z_enc * 0.197) + (z3 * -0.004) + 0.5

    @staticmethod
    def _to_encryptable_scalar(value: Any) -> float:
        """
        Convert arbitrary field values into a numeric scalar for CKKS encryption.
        Non-numeric values are represented by UTF-8 byte length to keep privacy accounting consistent.
        """
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(len(str(value).encode("utf-8")))

    def predict_proba(
        self,
        record: dict[str, Any],
        sensitive_fields: set[str] | None = None,
        capture_encrypted_payload: bool = False,
    ) -> tuple[float, float, list[str]] | tuple[float, float, list[str], dict[str, Any]]:
        """
        回傳 (probability, z_plain_for_logging, encrypted_feature_list)。
        """
        sensitive = sensitive_fields or set()

        z_plain_part = self.bias
        z_enc = self.encryptor.encrypt(0.0)
        encrypted_feature_list: list[str] = []

        encrypted_sensitive_values: dict[str, Any] = {}
        for feature in sorted(sensitive):
            if feature not in record:
                continue
            value = self._to_encryptable_scalar(record.get(feature, 0.0))
            encrypted_sensitive_values[feature] = self.encryptor.encrypt(value)
            encrypted_feature_list.append(feature)

        for feature, w in self.weights.items():
            value = float(record.get(feature, 0.0) or 0.0)
            if feature in encrypted_sensitive_values:
                enc_x = encrypted_sensitive_values[feature]
                z_enc = z_enc + (enc_x * w)
            else:
                z_plain_part += w * value

        z_enc = z_enc + z_plain_part

        # 優先走密文 sigmoid；若底層不支援，fallback 成先解密 z 再算 sigmoid。
        try:
            prob_enc = self._sigmoid_poly_encrypted(z_enc)
            prob = float(self.encryptor.decrypt(prob_enc))
        except Exception:
            z_value = float(self.encryptor.decrypt(z_enc))
            prob = self._sigmoid_plain(z_value)

        prob = max(0.0, min(1.0, prob))
        if capture_encrypted_payload:
            return round(prob, 4), float(z_plain_part), encrypted_feature_list, encrypted_sensitive_values

        return round(prob, 4), float(z_plain_part), encrypted_feature_list