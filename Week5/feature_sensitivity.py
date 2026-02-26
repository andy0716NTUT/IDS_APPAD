from typing import Dict, List

# 強制視為敏感（一定要 HE）的欄位名稱（使用「內部欄位名」風格）
FORCE_SENSITIVE_FEATURES = {
    "user_id",
    "ip_address",
    "location",
    "timestamp",
}

# 明確視為非敏感（不用 HE）的技術型欄位
FORCE_NON_SENSITIVE_FEATURES = {
    "session_duration",
    "failed_attempts",
    "behavioral_score",
    "anomaly",
    "device_type",
}


# 以欄位名稱關鍵字來判斷是否「可能」是敏感資訊
SENSITIVE_KEYWORDS = [
    # 身分／帳號
    "id",
    "user",
    "account",
    "uid",
    # 聯絡資訊
    "email",
    "mail",
    "phone",
    "tel",
    # 位置／地址
    "addr",
    "address",
    "location",
    "loc",
    "city",
    "region",
    # 裝置／網路識別
    "ip",
    "mac",
    "device",
    "imei",
    "imsi",
    # 金融
    "card",
    "bank",
    "salary",
    # 時間（可能與個人行為軌跡相關）
    "time",
    "timestamp",
]


def need_he_flag_for_feature(feature_name: str) -> int:
    """
    根據欄位名稱決定是否需要 HE。

    回傳:
        1 表示建議對此欄位做 HE / 加密保護
        0 表示可視為非敏感（就本作業假設）
    """
    name = feature_name.strip().lower()

    if not name:
        return 0

    if name in FORCE_SENSITIVE_FEATURES:
        return 1

    if name in FORCE_NON_SENSITIVE_FEATURES:
        return 0

    # 關鍵字粗略判斷
    for kw in SENSITIVE_KEYWORDS:
        if kw in name:
            return 1

    return 0


def explain_feature_sensitivity(feature_name: str) -> str:
    """
    給出簡短文字理由，方便在清單裡閱讀。
    """
    name = feature_name.strip().lower()

    if name in FORCE_SENSITIVE_FEATURES:
        return "in FORCE_SENSITIVE_FEATURES (直接或強識別資訊)"

    if name in FORCE_NON_SENSITIVE_FEATURES:
        return "in FORCE_NON_SENSITIVE_FEATURES (技術特徵，較難識別個人)"

    for kw in SENSITIVE_KEYWORDS:
        if kw in name:
            return f"matched keyword '{kw}' in SENSITIVE_KEYWORDS"

    return "default: treated as non-sensitive feature in this project"


class FeatureSensitivityClassifier:
    """
    封裝欄位層級敏感度判斷邏輯，提供較方便的呼叫介面。
    """

    def flag_feature(self, feature_name: str) -> int:
        """
        回傳單一欄位是否需要 HE 的 flag (0 或 1)。
        """
        return need_he_flag_for_feature(feature_name)

    def classify_features(self, feature_names: List[str]) -> List[Dict[str, str]]:
        """
        批次對多個欄位名稱做敏感度分類，回傳每個欄位的 flag 與理由。
        """
        results: List[Dict[str, str]] = []
        for name in feature_names:
            flag = need_he_flag_for_feature(name)
            reason = explain_feature_sensitivity(name)
            results.append(
                {
                    "feature": name,
                    "flag": str(flag),
                    "reason": reason,
                }
            )
        return results

    def sensitive_indices(self, record: Dict[str, object]) -> List[str]:
        """
        給一個欄位名稱 → 值 的 dict（例如一筆 record），
        回傳其中需要 HE 的欄位名稱清單。
        """
        sensitive_fields: List[str] = []
        for key in record.keys():
            if need_he_flag_for_feature(key) == 1:
                sensitive_fields.append(key)
        return sensitive_fields

