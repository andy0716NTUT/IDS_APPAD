import math

class LogisticRegressionPlain:
    """
    Simple Logistic Regression (Plaintext)
    z = w·x + b
    p = sigmoid(z)
    """

    def __init__(self):
        # 這裡先用「合理假權重」
        # 之後可以：
        # 1. 用 sklearn 訓練後塞進來
        # 2. 或從 NN / paper 轉來
        self.weights = {
            "session_duration": 0.003,
            "failed_attempts": 0.6,
            "behavioral_score": -0.04
        }
        self.bias = -1.5

    def sigmoid(self, z: float) -> float:
        return 1 / (1 + math.exp(-z))

    def predict_proba(self, record: dict) -> float:
        z = self.bias

        for feature, w in self.weights.items():
            value = record.get(feature, 0) or 0
            z += w * float(value)

        return round(self.sigmoid(z), 3)
