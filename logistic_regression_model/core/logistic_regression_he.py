from logistic_regression_model.inference.inference_tools import FEATURE_COLS


class LogisticRegressionHE:

    def __init__(self, sklearn_model, encryptor):

        self.encryptor = encryptor

        self.weights = sklearn_model.coef_[0]
        self.bias = float(sklearn_model.intercept_[0])

        self.features = FEATURE_COLS

    def encrypted_linear(self, record):

        z_enc = self.encryptor.encrypt(self.bias)

        for i, feature in enumerate(self.features):

            if feature not in record:
                continue

            value = record[feature]

            z_enc += value * self.weights[i]

        return z_enc