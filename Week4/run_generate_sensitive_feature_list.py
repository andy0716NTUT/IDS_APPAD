from pathlib import Path

import pandas as pd

from feature_sensitivity import FeatureSensitivityClassifier


# 與 Week2.sensitivity_classifier.run_dataset 中的欄位映射保持一致
COLUMN_MAPPING = {
    "User ID": "user_id",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
    # 額外補上在 dataset 中也會看到的欄位
    "Timestamp": "timestamp",
    "Device Type": "device_type",
    "Anomaly": "anomaly",
}


def main():
    # 專案根目錄（Week?/ 之上的那一層）
    base_dir = Path(__file__).resolve().parents[1]
    dataset_path = base_dir / "dataset" / "synthetic_web_auth_logs.csv"

    df = pd.read_csv(dataset_path)

    # 我們的敏感度是對「內部欄位名稱」來判斷
    internal_feature_names = list(set(COLUMN_MAPPING.values()))

    clf = FeatureSensitivityClassifier()
    results = clf.classify_features(internal_feature_names)

    # 同時附上原始 CSV 欄位名稱，方便對照
    rows = []
    inv_mapping = {}
    for csv_col, internal in COLUMN_MAPPING.items():
        inv_mapping.setdefault(internal, []).append(csv_col)

    for item in results:
        internal_name = item["feature_name"]
        src_cols = inv_mapping.get(internal_name, [])
        rows.append(
            {
                "feature_name": internal_name,
                "source_columns": ",".join(src_cols),
                "need_HE_flag": item["need_HE_flag"],
                "reason": item["reason"],
            }
        )

    out_df = pd.DataFrame(rows).sort_values("feature_name")

    output_path = base_dir / "Week4" / "sensitive_feature_list.csv"
    out_df.to_csv(output_path, index=False, encoding="utf-8")

    print(f"Saved sensitive feature list to: {output_path}")
    print(out_df)


if __name__ == "__main__":
    main()

