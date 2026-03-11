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
            return f"keyword match: '{kw}' → 可能含有身分/位置等敏感資訊"

    return "default non-sensitive (技術或統計性欄位)"


class FeatureSensitivityClassifier:
    """
    針對「欄位」設計的敏感性分類器。

    與 Week2 的 SensitivityClassifier（對「事件/紀錄」評分）不同，
    這裡只回答「這個欄位是否建議做 HE」→ flag ∈ {0, 1}
    """

    def flag_feature(self, feature_name: str) -> int:
        """
        單一欄位：回傳 0 / 1。
        """
        return need_he_flag_for_feature(feature_name)

    def classify_features(self, feature_names: List[str]) -> List[Dict[str, str]]:
        """
        批次對欄位名稱進行分類，回傳一個 list，之後可轉成 DataFrame/CSV。

        回傳中每筆 dict 內容：
            - feature_name
            - need_HE_flag (0/1)
            - reason
        """
        results = []
        for name in feature_names:
            flag = need_he_flag_for_feature(name)
            reason = explain_feature_sensitivity(name)
            results.append(
                {
                    "feature_name": name,
                    "need_HE_flag": flag,
                    "reason": reason,
                }
            )
        return results

    def sensitive_indices(self, record: Dict[str, float]) -> List[str]:
        """
        給一個 record（例如用在 AdaptiveModule 前），
        回傳其中「建議需要 HE」的欄位名稱清單，可直接丟給 sensitive_idx。
        """
        return [
            k for k in record.keys() if need_he_flag_for_feature(k) == 1
        ]

