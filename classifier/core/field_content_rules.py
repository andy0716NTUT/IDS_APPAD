"""
Per-field content-aware sensitivity rules.

Each analyzer inspects the actual VALUE of a field (not just its name)
and returns (FieldSensitivityLevel, reason_string).
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Dict, Tuple

from classifier.core.rules import SUSPICIOUS_LOCATIONS, SESSION_DURATION_THRESHOLDS


class FieldSensitivityLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Individual field analyzers
# ---------------------------------------------------------------------------

def _analyze_ip_address(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    ip = str(value).strip()
    if ip.startswith("192.168.") or ip.startswith("10."):
        return FieldSensitivityLevel.LOW, "internal_ip"
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return FieldSensitivityLevel.MEDIUM, "rfc1918_ip"
        except (IndexError, ValueError):
            pass
    return FieldSensitivityLevel.HIGH, "external_ip"


def _analyze_location(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    loc = str(value).strip()
    if loc in SUSPICIOUS_LOCATIONS:
        return FieldSensitivityLevel.HIGH, "suspicious_location"
    if loc.lower() in ("office", "home", "headquarter", "hq"):
        return FieldSensitivityLevel.LOW, "known_safe_location"
    return FieldSensitivityLevel.MEDIUM, "unknown_location"


def _analyze_failed_attempts(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return FieldSensitivityLevel.LOW, "non_numeric"
    if n >= 5:
        return FieldSensitivityLevel.HIGH, "many_failed_attempts"
    if n >= 3:
        return FieldSensitivityLevel.MEDIUM, "some_failed_attempts"
    return FieldSensitivityLevel.LOW, "few_failed_attempts"


def _analyze_behavioral_score(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return FieldSensitivityLevel.LOW, "non_numeric"
    if score < 40:
        return FieldSensitivityLevel.HIGH, "abnormal_behavior"
    if score < 60:
        return FieldSensitivityLevel.MEDIUM, "slightly_abnormal_behavior"
    return FieldSensitivityLevel.LOW, "normal_behavior"


def _analyze_session_duration(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    try:
        dur = float(value)
    except (TypeError, ValueError):
        return FieldSensitivityLevel.LOW, "non_numeric"
    if dur >= SESSION_DURATION_THRESHOLDS["LONG"]:
        return FieldSensitivityLevel.HIGH, "long_session"
    if dur >= 300:
        return FieldSensitivityLevel.MEDIUM, "moderate_session"
    return FieldSensitivityLevel.LOW, "short_session"


def _analyze_login_status(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    status = str(value).strip().lower()
    if status in ("fail", "failed"):
        return FieldSensitivityLevel.HIGH, "failed_login"
    return FieldSensitivityLevel.LOW, "successful_login"


def _analyze_user_id(_value: Any) -> Tuple[FieldSensitivityLevel, str]:
    return FieldSensitivityLevel.HIGH, "pii_field"


def _analyze_timestamp(value: Any) -> Tuple[FieldSensitivityLevel, str]:
    ts = str(value).strip()
    try:
        if "T" in ts:
            hour = int(ts.split("T")[1].split(":")[0])
        elif " " in ts:
            hour = int(ts.split(" ")[1].split(":")[0])
        else:
            return FieldSensitivityLevel.MEDIUM, "unparseable_timestamp"
        if hour < 6 or hour >= 22:
            return FieldSensitivityLevel.HIGH, "night_hours"
        return FieldSensitivityLevel.LOW, "daytime_hours"
    except (IndexError, ValueError):
        return FieldSensitivityLevel.MEDIUM, "unparseable_timestamp"


def _analyze_device_type(_value: Any) -> Tuple[FieldSensitivityLevel, str]:
    return FieldSensitivityLevel.LOW, "non_identifying"


def _analyze_anomaly(_value: Any) -> Tuple[FieldSensitivityLevel, str]:
    return FieldSensitivityLevel.LOW, "derived_metric"


# ---------------------------------------------------------------------------
# Registry: field_name -> analyzer function
# ---------------------------------------------------------------------------

FIELD_ANALYZERS: Dict[str, Callable[[Any], Tuple[FieldSensitivityLevel, str]]] = {
    "ip_address": _analyze_ip_address,
    "location": _analyze_location,
    "failed_attempts": _analyze_failed_attempts,
    "behavioral_score": _analyze_behavioral_score,
    "session_duration": _analyze_session_duration,
    "login_status": _analyze_login_status,
    "user_id": _analyze_user_id,
    "timestamp": _analyze_timestamp,
    "device_type": _analyze_device_type,
    "anomaly": _analyze_anomaly,
}
