# rules.py

MODEL_FEATURES = [
    "ip_address",
    "login_status",
    "location",
    "session_duration",
    "failed_attempts",
    "behavioral_score"
]

HIGH_RISK_RULES = {
    "external_ip": 0.4,
    "failed_login": 0.2,
    "suspicious_location": 0.35,
    "long_session": 0.25,
    "many_failed_attempts": 0.4,
    "some_failed_attempts": 0.25,
    "abnormal_behavior": 0.4,
    "slightly_abnormal_behavior": 0.2
}

THRESHOLDS = {
    "HIGH": 0.7,
    "MEDIUM": 0.4
}

SUSPICIOUS_LOCATIONS = {
    "Mars"
}

SESSION_DURATION_THRESHOLDS = {
    "LONG": 600
}
