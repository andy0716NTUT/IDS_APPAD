from logistic_regression_model.core.server_lr import ServerLR


class APPADPipeline:

    def __init__(self, adaptive_module, client, he_model):
        self.adaptive = adaptive_module
        self.client = client
        self.server = ServerLR(he_model)

    def run(self, record, sensitive_cols):

        protected = self.adaptive.protect(
            record,
            flag=True,
            sensitive_idx=sensitive_cols
        )

        merged = {}

        merged.update(protected["plain"])
        merged.update(protected["encrypted"])

        z_enc = self.server.infer(merged)

        prob = self.client.decrypt_and_sigmoid(z_enc)

        return prob