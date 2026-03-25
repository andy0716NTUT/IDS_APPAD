from __future__ import annotations

from typing import Any


class CKKSEncryptor:
    """
    使用 TenSEAL 實作的 CKKS 同態加密封裝。

    - 對數值型資料（int / float / numpy scalar）做加密
    - 回傳的是 CKKS 向量密文（預設以單一元素向量承載 scalar）

    使用前請先安裝依賴：
        pip install tenseal
    """

    def __init__(
        self,
        poly_modulus_degree: int = 8192,
        coeff_mod_bit_sizes: list[int] | None = None,
        global_scale_bits: int = 40,
    ) -> None:
        try:
            import tenseal as ts  # type: ignore
        except ImportError as e:  # pragma: no cover - 明確錯誤訊息
            raise ImportError(
                "需要安裝 tenseal 套件才能使用 CKKSEncryptor，"
                "請先執行: pip install tenseal"
            ) from e

        bit_sizes = coeff_mod_bit_sizes or [60, 40, 40, 60]
        self._ts = ts
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=bit_sizes,
        )
        self.context.global_scale = 2 ** global_scale_bits
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()

    # 給 AdaptiveModule 用的介面
    def encrypt(self, value: Any):
        """
        將單一數值加密成 CKKS 密文向量（長度 1）。
        對非數值類型（例如字串）會先嘗試轉成 float，不行就直接丟出錯誤。
        """
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as e:
            raise TypeError(
                f"CKKSEncryptor 目前只支援數值型資料，收到的值為: {value!r}"
            ) from e

        return self._ts.ckks_vector(self.context, [numeric_value])

    # 方便你之後要 demo 解密或驗證結果時使用（目前 Week6 流程暫時沒用到）
    def decrypt(self, ciphertext):
        decrypted = ciphertext.decrypt()
        if len(decrypted) == 1:
            return float(decrypted[0])
        return [float(v) for v in decrypted]

