from pathlib import Path
from typing import Dict, Any

import pandas as pd

from Week6.mixed_protection import MixedProtectionPipeline


# 與 Week2 / Week4 保持一致的欄位映射：CSV → 內部欄位名稱
COLUMN_MAPPING: Dict[str, str] = {
    "User ID": "user_id",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
    "Timestamp": "timestamp",
    "Device Type": "device_type",
    "Anomaly": "anomaly",
}


def load_one_record() -> Dict[str, Any]:
    """
    從 dataset/synthetic_web_auth_logs.csv 讀取一筆資料，
    並轉成使用「內部欄位名稱」的 dict，方便後續 APPAD / classifier 使用。
    """
    base_dir = Path(__file__).resolve().parents[1]
    dataset_path = base_dir / "dataset" / "synthetic_web_auth_logs.csv"

    df = pd.read_csv(dataset_path)
    if df.empty:
        raise RuntimeError("Dataset is empty.")

    row = df.iloc[0]  # 只示範第一筆

    record: Dict[str, Any] = {}
    for csv_col, internal_name in COLUMN_MAPPING.items():
        if csv_col in row:
            record[internal_name] = row[csv_col]

    return record


def main() -> None:
    pipeline = MixedProtectionPipeline()

    record = load_one_record()
    print("[原始 record (internal names)]:")
    print(record)
    print()

    # 1️⃣ 開啟 HE（敏感欄位走 encrypted）
    protected_with_he = pipeline.protect_record(record, enable_he=True)
    print("=== enable_he = True → 明文 / 假加密 並存 ===")
    print("plain:", protected_with_he["plain"])
    print("encrypted:", protected_with_he["encrypted"])
    print()

    # 2️⃣ 關閉 HE（全部當作 plain）
    protected_plain_only = pipeline.protect_record(record, enable_he=False)
    print("=== enable_he = False → 全部視為明文 ===")
    print("plain:", protected_plain_only["plain"])
    print("encrypted:", protected_plain_only["encrypted"])


if __name__ == "__main__":
    main()

