# client_decision.py
import math

class ClientDecision:
    def __init__(self, threshold=0.5):
        self.threshold = threshold

    def decide(self, z):
        if isinstance(z, str):
            z = self._decrypt(z)

        prob = 1 / (1 + math.exp(-z))
        return prob > self.threshold, prob

    def _decrypt(self, enc_z):
        # 🚧 PoC stub：假設已解密成數值
        return 0.63
