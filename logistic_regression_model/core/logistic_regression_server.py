class ServerLR:

    def __init__(self, weights: dict, bias: float = 0.0):
        self.weights = weights
        self.bias = bias

    def infer(self, payload: dict):

        z = self.bias

        # plaintext features
        for k, v in payload["plain"].items():
            w = self.weights.get(k, 0.0)
            z += w * v

        # encrypted features
        for k, enc_v in payload["encrypted"].items():
            w = self.weights.get(k, 0.0)

            term = enc_v * w
            z = z + term

        return z