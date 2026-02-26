"""
Week5 - Finalized Feature Sensitivity Classifier

本模組整理自 Week4 的欄位層級敏感度 classifier，提供穩定匯入介面：

- `need_he_flag_for_feature(feature_name: str) -> int`
- `FeatureSensitivityClassifier`
"""

from .feature_sensitivity import (
    need_he_flag_for_feature,
    FeatureSensitivityClassifier,
)

