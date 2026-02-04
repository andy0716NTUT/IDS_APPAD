import time
import random
from Week2.sensitivity_classifier.classifier import SensitivityClassifier


class PlaintextDetector:
    """
    Fast anomaly detection (no encryption)
    """
    def detect(self, record: dict) -> float:
        # 簡單模擬一個 anomaly score
        return random.uniform(0, 0.4)


class EncryptedDetector:
    """
    Privacy-preserving anomaly detection (mock version)
    """
    def detect(self, record: dict) -> float:
        # 模擬同態加密計算延遲
        time.sleep(0.2)  # 200 ms
        return random.uniform(0.6, 1.0)


class APPADCore:
    """
    Adaptive Privacy-Preserving Anomaly Detection Core
    """

    def __init__(self):
        self.sensitivity_classifier = SensitivityClassifier()
        self.plain_detector = PlaintextDetector()
        self.encrypted_detector = EncryptedDetector()

    def process(self, record: dict):
        """
        Main entry point of APPAD
        """

        # Step 1: Sensitivity classification
        sensitivity_result = self.sensitivity_classifier.classify(record)
        level = sensitivity_result["sensitivity_level"]

        # Step 2: Adaptive routing
        start_time = time.time()

        if level == "HIGH":
            score = self.encrypted_detector.detect(record)
            method = "encrypted"
        else:
            score = self.plain_detector.detect(record)
            method = "plaintext"

        latency_ms = (time.time() - start_time) * 1000

        # Step 3: Unified output
        return {
            "sensitivity_level": level,
            "is_sensitive": sensitivity_result["is_sensitive"],
            "anomaly_score": round(score, 2),
            "detection_method": method,
            "latency_ms": round(latency_ms, 1)
        }