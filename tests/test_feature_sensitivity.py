"""Tests for content-aware field-level sensitivity classification."""
from __future__ import annotations

from classifier.core.feature_sensitivity import FeatureSensitivityClassifier, FieldAnalysisResult
from classifier.core.field_content_rules import FieldSensitivityLevel


clf = FeatureSensitivityClassifier()


# --- Content-aware analyze_field ---

def test_internal_ip_is_low():
    r = clf.analyze_field("ip_address", "192.168.1.1")
    assert r.level == FieldSensitivityLevel.LOW

def test_external_ip_is_high():
    r = clf.analyze_field("ip_address", "203.0.113.50")
    assert r.level == FieldSensitivityLevel.HIGH

def test_rfc1918_ip_is_medium():
    r = clf.analyze_field("ip_address", "172.16.0.1")
    assert r.level == FieldSensitivityLevel.MEDIUM

def test_normal_behavior_is_low():
    r = clf.analyze_field("behavioral_score", 85)
    assert r.level == FieldSensitivityLevel.LOW

def test_abnormal_behavior_is_high():
    r = clf.analyze_field("behavioral_score", 15)
    assert r.level == FieldSensitivityLevel.HIGH

def test_slightly_abnormal_behavior_is_medium():
    r = clf.analyze_field("behavioral_score", 50)
    assert r.level == FieldSensitivityLevel.MEDIUM

def test_few_failed_attempts_is_low():
    r = clf.analyze_field("failed_attempts", 1)
    assert r.level == FieldSensitivityLevel.LOW

def test_many_failed_attempts_is_high():
    r = clf.analyze_field("failed_attempts", 5)
    assert r.level == FieldSensitivityLevel.HIGH

def test_success_login_is_low():
    r = clf.analyze_field("login_status", "success")
    assert r.level == FieldSensitivityLevel.LOW

def test_failed_login_is_high():
    r = clf.analyze_field("login_status", "failed")
    assert r.level == FieldSensitivityLevel.HIGH

def test_user_id_always_high():
    r = clf.analyze_field("user_id", 12345)
    assert r.level == FieldSensitivityLevel.HIGH

def test_device_type_always_low():
    r = clf.analyze_field("device_type", "mobile")
    assert r.level == FieldSensitivityLevel.LOW

def test_daytime_timestamp_is_low():
    r = clf.analyze_field("timestamp", "2026-01-15T14:30:00")
    assert r.level == FieldSensitivityLevel.LOW

def test_night_timestamp_is_high():
    r = clf.analyze_field("timestamp", "2026-01-15T03:00:00")
    assert r.level == FieldSensitivityLevel.HIGH


# --- Dynamic sensitive_indices ---

LOW_RECORD = {
    "user_id": 1,
    "ip_address": "192.168.1.1",
    "location": "office",
    "session_duration": 60,
    "failed_attempts": 0,
    "behavioral_score": 90,
    "login_status": "success",
    "timestamp": "2026-01-15T14:00:00",
    "device_type": "desktop",
}

HIGH_RECORD = {
    "user_id": 999,
    "ip_address": "203.0.113.50",
    "location": "Mars",
    "session_duration": 700,
    "failed_attempts": 5,
    "behavioral_score": 15,
    "login_status": "failed",
    "timestamp": "2026-01-15T03:00:00",
    "device_type": "mobile",
}

def test_low_record_encrypts_fewer_fields():
    low_fields = clf.sensitive_indices(LOW_RECORD)
    high_fields = clf.sensitive_indices(HIGH_RECORD)
    assert len(low_fields) < len(high_fields)

def test_low_record_only_pii():
    """LOW-content record should only encrypt user_id (PII)."""
    fields = clf.sensitive_indices(LOW_RECORD)
    assert "user_id" in fields
    assert "ip_address" not in fields  # internal IP -> LOW
    assert "behavioral_score" not in fields

def test_high_record_encrypts_many():
    fields = clf.sensitive_indices(HIGH_RECORD)
    assert "user_id" in fields
    assert "ip_address" in fields
    assert "login_status" in fields
    assert "failed_attempts" in fields

def test_medium_fields_encrypted_when_record_high():
    """MEDIUM fields should be encrypted when record_sensitivity=HIGH."""
    record = {
        "ip_address": "172.16.0.1",  # MEDIUM
        "behavioral_score": 50,       # MEDIUM
        "user_id": 1,                 # HIGH
    }
    without = clf.sensitive_indices(record, record_sensitivity="MEDIUM")
    with_high = clf.sensitive_indices(record, record_sensitivity="HIGH")
    assert "user_id" in without  # HIGH field always included
    assert "ip_address" not in without  # MEDIUM not included for MEDIUM record
    assert "ip_address" in with_high  # MEDIUM included for HIGH record


# --- Backward compatibility ---

def test_legacy_flag_feature_unchanged():
    assert clf.flag_feature("user_id") == 1
    assert clf.flag_feature("session_duration") == 0
    assert clf.flag_feature("ip_address") == 1

def test_legacy_classify_features_unchanged():
    results = clf.classify_features(["user_id", "session_duration"])
    assert results[0]["need_HE_flag"] == 1
    assert results[1]["need_HE_flag"] == 0
