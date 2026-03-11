from logistic_regression_model.inference.inference_tools import FEATURE_COLS


class ServerLR:

    def __init__(self, he_model):

        self.he_model = he_model

    def infer(self, record):

        z_enc = self.he_model.encrypted_linear(record)

        return z_enc