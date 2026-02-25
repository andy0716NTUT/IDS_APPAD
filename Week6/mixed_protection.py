from typing import Dict, Any

from Week3.appad_core.adaptive_module import AdaptiveModule
from Week5.feature_sensitivity import FeatureSensitivityClassifier


class MixedProtectionPipeline:
    """
    根據欄位敏感度 classifier 產生的 flag (0/1)，決定資料要走
    明文 / 假加密(未來可換成 HE) 的處理流程，達成「明文/密文並存」。
    """

    def __init__(self, encryptor: Any | None = None) -> None:
        # 欄位層級敏感度 classifier（Week5）
        self.feature_clf = FeatureSensitivityClassifier()
        # APPAD 的欄位保護模組（Week3）
        self.adaptive_module = AdaptiveModule(encryptor=encryptor)

    def get_sensitive_fields(self, record: Dict[str, Any]) -> list[str]:
        """
        使用欄位敏感度 classifier，找出這筆 record 中需要 HE 的欄位名稱清單。
        """
        return self.feature_clf.sensitive_indices(record)

    def protect_record(
        self,
        record: Dict[str, Any],
        enable_he: bool = True,
    ) -> Dict[str, Dict[str, Any]]:
        """
        對單一 record 做「混合保護」：
        - 若 enable_he=True：sensitive 欄位丟到 encrypted，其餘維持在 plain
        - 若 enable_he=False：全部都視為 plain（模擬關閉 HE）

        回傳格式與 AdaptiveModule.protect 一致：
        {
            "plain": {...},
            "encrypted": {...}
        }
        """
        sensitive_idx = self.get_sensitive_fields(record)
        return self.adaptive_module.protect(
            x=record,
            flag=enable_he,
            sensitive_idx=sensitive_idx,
        )

