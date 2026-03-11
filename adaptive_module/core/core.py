import time

from classifier.core.classifier import SensitivityClassifier

from adaptive_module.core.mixed_protection import MixedProtectionPipeline

from ckks_homomorphic_encryption.he_encryptor import PaillierEncryptor

from logistic_regression_model.core.logistic_regression_plain import LogisticRegressionPlain
from logistic_regression_model.core.logistic_regression_he import LogisticRegressionHE

from logistic_regression_model.server.server_lr import ServerLR

from logistic_regression_model.core.he_client import HEClient

from logistic_regression_model.inference.inference_tools import load_trained_model, resolve_model_path


class APPADCore:

    def __init__(self):

        # sensitivity classifier
        self.classifier = SensitivityClassifier()

        # encryptor
        self.encryptor = PaillierEncryptor()

        # protection pipeline
        self.pipeline = MixedProtectionPipeline(encryptor=self.encryptor)

        # 載入 sklearn model
        model_path = resolve_model_path()
        sklearn_model = load_trained_model(model_path)

        # plaintext LR
        self.lr_plain = LogisticRegressionPlain(sklearn_model)

        # HE LR
        self.lr_he = LogisticRegressionHE(sklearn_model, self.encryptor)

        # server
        self.server = ServerLR(self.lr_he)

        # HE client
        self.he_client = HEClient(self.encryptor)

    def process(self, record: dict) -> dict:

        start = time.time()

        # plaintext inference
        plaintext_score = self.lr_plain.predict_proba(record)

        # HE protection
        payload = self.pipeline.protect_record(
            record,
            enable_he=True
        )

        # encrypted inference
        encrypted_z = self.server.infer(payload["encrypted"] | payload["plain"])

        encrypted_score = self.he_client.decrypt_and_sigmoid(encrypted_z)

        latency = round((time.time() - start) * 1000, 2)

        return {
            "plaintext_score": round(plaintext_score, 6),
            "encrypted_score": round(encrypted_score, 6),
            "difference": round(abs(plaintext_score - encrypted_score), 6),
            "latency_ms": latency
        }