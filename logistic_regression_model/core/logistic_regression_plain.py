import math
from logistic_regression_model.inference.inference_tools import FEATURE_COLS


class LogisticRegressionPlain:
    """
    Logistic Regression (Plaintext)
    使用 sklearn 訓練好的模型權重
    """

    def __init__(self, sklearn_model):

        # sklearn LR
        self.weights = sklearn_model.coef_[0]
        self.bias = float(sklearn_model.intercept_[0])

        # 與 inference_tools 保持一致
        self.feature_cols = FEATURE_COLS

    def sigmoid(self, z: float) -> float:
        return 1 / (1 + math.exp(-z))

    def predict_proba(self, record: dict) -> float:

        z = self.bias

        for i, feature in enumerate(self.feature_cols):

            value = record.get(feature, 0)

            if value is None:
                value = 0

            z += self.weights[i] * float(value)

        return round(self.sigmoid(z), 3)