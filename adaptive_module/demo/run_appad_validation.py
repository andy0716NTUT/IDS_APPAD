import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adaptive_module.core.mixed_protection import MixedProtectionPipeline
from ckks_homomorphic_encryption.he_encryptor import PaillierEncryptor

from logistic_regression_model.core.logistic_regression_plain import LogisticRegressionPlain
from logistic_regression_model.core.logistic_regression_server import ServerLR

class DummyModel:

    def predict_proba(self, X):

        # fake logistic regression result
        import numpy as np

        score = (
            X[0][0] * 0.3 +
            X[0][1] * 0.2 +
            X[0][2] * 0.4 +
            X[0][3] * 0.1
        )

        return np.array([[1-score, score]])
    
def main():

    encryptor = PaillierEncryptor()

    pipeline = MixedProtectionPipeline(encryptor=encryptor)

    dummy = DummyModel()
    lr_plain = LogisticRegressionPlain(dummy)
    lr_server = ServerLR(encryptor)

    record = {
        "session_duration": 12.3,
        "failed_attempts": 2,
        "behavioral_score": 0.72,
        "login_status": 1,
    }

    print("===== 原始資料 =====")
    print(record)
    print()

    # Step1: Adaptive Protection
    protected = pipeline.protect_record(record, enable_he=True)

    plain_data = protected["plain"]
    encrypted_data = protected["encrypted"]

    print("===== Plain Features =====")
    print(plain_data)

    print("===== Encrypted Features =====")
    print(encrypted_data)

    print()

    # Step2: 明文推論
    plain_score = lr_plain.predict(record)

    print("Plain inference result:")
    print(plain_score)

    print()

    # Step3: 密文推論
    encrypted_score = lr_server.predict(plain_data, encrypted_data)

    decrypted_score = encryptor.decrypt(encrypted_score)

    print("Encrypted inference result (after decrypt):")
    print(decrypted_score)

    print()

    print("Difference:")
    print(abs(plain_score - decrypted_score))


if __name__ == "__main__":
    main()