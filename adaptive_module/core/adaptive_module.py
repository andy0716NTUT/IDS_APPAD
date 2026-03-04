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
        #  PoC stub（之後直接換成 CKKS）
        if self.encryptor:
            return self.encryptor.encrypt(value)
        return f"enc({value})"
