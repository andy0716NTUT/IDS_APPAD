import time

from Week2.sensitivity_classifier.classifier import SensitivityClassifier
from Week3.appad_core.lr_plain import LogisticRegressionPlain


class APPADCore:
    def __init__(self):
        self.classifier = SensitivityClassifier()
        self.lr_plain = LogisticRegressionPlain()

    def process(self, record: dict) -> dict:
        start_time = time.time()

        # 1️⃣ 敏感性判斷
        cls = self.classifier.classify(record)

        encryption_required = cls["encryption_required"]

        # 2️⃣ LR 明文推論（現在只做這條路）
        anomaly_score = self.lr_plain.predict_proba(record)

        # 3️⃣ 模擬延遲
        if encryption_required:
            detection_method = "encrypted (stub)"
            time.sleep(0.2)
        else:
            detection_method = "plaintext"
            time.sleep(0.02)

        latency_ms = round((time.time() - start_time) * 1000, 1)

        return {
            "sensitivity_level": cls["sensitivity_level"],
            "is_sensitive": cls["is_sensitive"],
            "risk_score": cls["risk_score"],
            "anomaly_score": anomaly_score,
            "detection_method": detection_method,
            "latency_ms": latency_ms,
            "reasons": cls["reasons"]
        }
