from Week2.sensitivity_classifier.rules import (
    HIGH_RISK_RULES,
    THRESHOLDS,
    SUSPICIOUS_LOCATIONS,
    SESSION_DURATION_THRESHOLDS
)

class SensitivityClassifier:
    """
    APPAD - Data Sensitivity Classification Module

    以規則權重計分後，依門檻輸出 LOW / MEDIUM / HIGH。
    """

    def classify(self, record: dict):
        risk_score = 0.0
        reasons = []

        # IP rule
        ip = str(record.get("ip_address", "")).strip()
        if ip and not (ip.startswith("192.168") or ip.startswith("10.")):
            risk_score += HIGH_RISK_RULES["external_ip"]
            reasons.append("external_ip")

        # Failed attempts
        failed = record.get("failed_attempts", 0) or 0
        if failed >= 5:
            risk_score += HIGH_RISK_RULES["many_failed_attempts"]
            reasons.append("many_failed_attempts")
        elif failed >= 3:
            risk_score += HIGH_RISK_RULES["some_failed_attempts"]
            reasons.append("some_failed_attempts")

        # Login status
        login_status = str(record.get("login_status", "")).strip().lower()
        if login_status in ("fail", "failed"):
            risk_score += HIGH_RISK_RULES["failed_login"]
            reasons.append("failed_login")

        # Location
        location = str(record.get("location", "")).strip()
        if location in SUSPICIOUS_LOCATIONS:
            risk_score += HIGH_RISK_RULES["suspicious_location"]
            reasons.append("suspicious_location")

        # Session duration
        session_duration = record.get("session_duration", 0) or 0
        if session_duration >= SESSION_DURATION_THRESHOLDS["LONG"]:
            risk_score += HIGH_RISK_RULES["long_session"]
            reasons.append("long_session")

        # Behavioral score
        behavior = record.get("behavioral_score", 100)
        if behavior < 40:
            risk_score += HIGH_RISK_RULES["abnormal_behavior"]
            reasons.append("abnormal_behavior")
        elif behavior < 60:
            risk_score += HIGH_RISK_RULES["slightly_abnormal_behavior"]
            reasons.append("slightly_abnormal_behavior")

        risk_score = min(risk_score, 1.0)

        if risk_score >= THRESHOLDS["HIGH"]:
            level = "HIGH"
        elif risk_score >= THRESHOLDS["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "is_sensitive": level in ("MEDIUM", "HIGH"),
            "risk_score": round(risk_score, 2),
            "sensitivity_level": level,
            "encryption_required": level == "HIGH",
            "reasons": reasons
        }