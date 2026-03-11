from typing import Dict, List, Any


class AdaptiveModule:

    def __init__(self, encryptor=None):

        # Paillier encryptor instance
        self.encryptor = encryptor

    def _is_numeric(self, value: Any) -> bool:
        """
        檢查 value 是否能轉成 float
        Paillier 只能處理 numeric
        """
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False

    def protect(
        self,
        x: Dict[str, Any],
        flag: bool,
        sensitive_idx: List[str]
    ) -> Dict:

        plain = {}
        encrypted = {}

        for k, v in x.items():

            # sensitive feature 且為 numeric 才加密
            if flag and k in sensitive_idx and self._is_numeric(v):

                encrypted[k] = self._encrypt(v)

            else:

                plain[k] = v

        return {
            "plain": plain,
            "encrypted": encrypted
        }

    def _encrypt(self, value):

        if self.encryptor:
            return self.encryptor.encrypt(value)

        return value