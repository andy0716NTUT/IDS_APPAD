# logistic_regression_server.py
class ServerLR:
    def __init__(self, weights: dict, bias: float = 0.0):
        self.weights = weights
        self.bias = bias

    def infer(self, payload: dict):
        z = self.bias

        # 明文部分
        for k, v in payload["plain"].items():
            z += self.weights.get(k, 0.0) * v

        # 密文部分（PoC：字串模擬）
        for k, v in payload["encrypted"].items():
            z = self._enc_add(z, self._enc_mul(self.weights.get(k, 0.0), v))

        return z

    def _enc_mul(self, w, enc_x):
        return f"({w}*{enc_x})"

    def _enc_add(self, z, term):
        return f"({z}+{term})"
