# adaptive_module.py
from typing import Dict, List

class AdaptiveModule:
    def __init__(self, encryptor=None):
        """
        encryptor: 之後可以換成 CKKS encryptor
        目前先用假加密（stub）
        """
        self.encryptor = encryptor

    def protect(
        self,
        x: Dict[str, float],
        flag: bool,
        sensitive_idx: List[str]
    ) -> Dict:
        plain = {}
        encrypted = {}

        for k, v in x.items():
            if flag and k in sensitive_idx:
                encrypted[k] = self._encrypt(v)
            else:
                plain[k] = v

        return {
            "plain": plain,
            "encrypted": encrypted
        }

    def _encrypt(self, value):
        """
        封裝加密邏輯：
        - 若有真正的 encryptor（例如 PaillierEncryptor），優先嘗試使用
        - 若 encryptor 無法處理該型別（例如非數值），則退回到 PoC stub：enc(value)
        - 若沒有傳入 encryptor，一律使用 stub
        """
        # 先嘗試用真正的 encryptor（例如 Paillier）
        if self.encryptor is not None:
            try:
                return self.encryptor.encrypt(value)
            except TypeError:
                # 例如 PaillierEncryptor 僅支援數值型別時，對字串會丟出 TypeError
                # 在這裡降級成 demo 用的假加密字串，避免整個流程噴錯中斷。
                return f"enc({value})"

        # 沒有傳入 encryptor → 一律使用 stub
        return f"enc({value})"
