from __future__ import annotations

from typing import Any


class PaillierEncryptor:
    """
    使用 `phe` 套件實作的簡單 Paillier 同態加密封裝。

    - 對數值型資料（int / float / numpy 數值）做加密
    - 回傳的是 Paillier 密文物件，可在之後做同態加法等運算

    使用前請先安裝依賴：
        pip install phe
    """

    def __init__(self, key_length: int = 1024) -> None:
        try:
            from phe import paillier  # type: ignore
        except ImportError as e:  # pragma: no cover - 明確錯誤訊息
            raise ImportError(
                "需要安裝 `phe` 套件才能使用 PaillierEncryptor，"
                "請先執行：pip install phe"
            ) from e

        self._paillier = paillier
        self.public_key, self._private_key = paillier.generate_paillier_keypair(
            n_length=key_length
        )

    # 給 AdaptiveModule 用的介面
    def encrypt(self, value: Any):
        """
        將單一數值加密成 Paillier 密文。
        對非數值類型（例如字串）會先嘗試轉成 float，不行就直接丟出錯誤。
        """
        # numpy scalar / int / float 統一走 float
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as e:
            raise TypeError(
                f"PaillierEncryptor 目前只支援數值型資料，收到的值為: {value!r}"
            ) from e

        return self.public_key.encrypt(numeric_value)

    # 方便你之後要 demo 解密或驗證結果時使用（目前 Week6 流程暫時沒用到）
    def decrypt(self, ciphertext):
        return self._private_key.decrypt(ciphertext)

