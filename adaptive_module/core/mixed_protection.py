from typing import Dict, Any

from adaptive_module.core.adaptive_module import AdaptiveModule
from classifier.core.feature_sensitivity import FeatureSensitivityClassifier


class MixedProtectionPipeline:

    def __init__(self, encryptor) -> None:

        # feature sensitivity classifier
        self.feature_clf = FeatureSensitivityClassifier()

        # APPAD adaptive module
        self.adaptive_module = AdaptiveModule(encryptor=encryptor)

    def get_sensitive_fields(self, record: Dict[str, Any]) -> list[str]:

        return self.feature_clf.sensitive_indices(record)

    def protect_record(
        self,
        record: Dict[str, Any],
        enable_he: bool = True,
    ) -> Dict[str, Dict[str, Any]]:

        sensitive_idx = self.get_sensitive_fields(record)

        return self.adaptive_module.protect(
            x=record,
            flag=enable_he,
            sensitive_idx=sensitive_idx,
        )