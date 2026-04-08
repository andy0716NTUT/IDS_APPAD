from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from classifier.core.field_content_rules import (
    FIELD_ANALYZERS,
    FieldSensitivityLevel,
)

# ---------------------------------------------------------------------------
# Legacy static lists (kept for backward compatibility)
# ---------------------------------------------------------------------------

FORCE_SENSITIVE_FEATURES = {
    "user_id",
    "ip_address",
    "location",
    "timestamp",
}

FORCE_NON_SENSITIVE_FEATURES = {
    "session_duration",
    "failed_attempts",
    "behavioral_score",
    "anomaly",
    "device_type",
}

SENSITIVE_KEYWORDS = [
    "id", "user", "account", "uid",
    "email", "mail", "phone", "tel",
    "addr", "address", "location", "loc", "city", "region",
    "ip", "mac", "device", "imei", "imsi",
    "card", "bank", "salary",
    "time", "timestamp",
]


# ---------------------------------------------------------------------------
# Legacy name-only helpers (unchanged API)
# ---------------------------------------------------------------------------

def need_he_flag_for_feature(feature_name: str) -> int:
    name = feature_name.strip().lower()
    if not name:
        return 0
    if name in FORCE_SENSITIVE_FEATURES:
        return 1
    if name in FORCE_NON_SENSITIVE_FEATURES:
        return 0
    for kw in SENSITIVE_KEYWORDS:
        if kw in name:
            return 1
    return 0


def explain_feature_sensitivity(feature_name: str) -> str:
    name = feature_name.strip().lower()
    if name in FORCE_SENSITIVE_FEATURES:
        return "in FORCE_SENSITIVE_FEATURES (直接或強識別資訊)"
    if name in FORCE_NON_SENSITIVE_FEATURES:
        return "in FORCE_NON_SENSITIVE_FEATURES (技術特徵，較難識別個人)"
    for kw in SENSITIVE_KEYWORDS:
        if kw in name:
            return f"keyword match: '{kw}' → 可能含有身分/位置等敏感資訊"
    return "default non-sensitive (技術或統計性欄位)"


# ---------------------------------------------------------------------------
# Content-aware result type
# ---------------------------------------------------------------------------

@dataclass
class FieldAnalysisResult:
    field_name: str
    level: FieldSensitivityLevel
    reason: str


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class FeatureSensitivityClassifier:
    """
    Supports both legacy name-only and new content-aware classification.
    """

    # --- Legacy name-only API (unchanged) ---

    def flag_feature(self, feature_name: str) -> int:
        return need_he_flag_for_feature(feature_name)

    def classify_features(self, feature_names: List[str]) -> List[Dict[str, str]]:
        results = []
        for name in feature_names:
            flag = need_he_flag_for_feature(name)
            reason = explain_feature_sensitivity(name)
            results.append({
                "feature_name": name,
                "need_HE_flag": flag,
                "reason": reason,
            })
        return results

    # --- New content-aware API ---

    def analyze_field(self, field_name: str, value: Any) -> FieldAnalysisResult:
        """Analyze a single field based on its name AND value."""
        name = field_name.strip().lower()
        analyzer = FIELD_ANALYZERS.get(name)
        if analyzer is not None:
            level, reason = analyzer(value)
            return FieldAnalysisResult(field_name=name, level=level, reason=reason)
        # Fallback: use legacy name-only logic
        flag = need_he_flag_for_feature(name)
        level = FieldSensitivityLevel.HIGH if flag else FieldSensitivityLevel.LOW
        reason = explain_feature_sensitivity(name)
        return FieldAnalysisResult(field_name=name, level=level, reason=reason)

    def analyze_record(self, record: Dict[str, Any]) -> Dict[str, FieldAnalysisResult]:
        """Analyze all fields in a record based on content."""
        return {k: self.analyze_field(k, v) for k, v in record.items()}

    def sensitive_indices(
        self,
        record: Dict[str, Any],
        record_sensitivity: str | None = None,
    ) -> List[str]:
        """
        Return field names that should be encrypted.

        If called with raw record values, uses content-aware analysis.
        Encryption policy:
          - HIGH fields: always encrypt
          - MEDIUM fields: encrypt if record_sensitivity is HIGH
          - LOW fields: never encrypt
        """
        analysis = self.analyze_record(record)
        result = []
        for name, field_result in analysis.items():
            if field_result.level == FieldSensitivityLevel.HIGH:
                result.append(name)
            elif field_result.level == FieldSensitivityLevel.MEDIUM:
                if record_sensitivity and record_sensitivity.upper() == "HIGH":
                    result.append(name)
        return result
