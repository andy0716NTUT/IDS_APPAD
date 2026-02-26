from pathlib import Path
from typing import Dict, Any

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.patches import Patch

from Week6.mixed_protection import MixedProtectionPipeline
from Week6.he_encryptor import PaillierEncryptor


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


def visualize_protection_result(
    protected_with_he: Dict[str, Dict[str, Any]],
    protected_plain_only: Dict[str, Dict[str, Any]],
) -> None:
    """
    將 enable_he=True / False 兩種情境下，各欄位是明文還是加密的狀態視覺化。

    會在 Week6 資料夾輸出一張 PNG 圖：
    - X 軸：欄位名稱
    - Y 軸：兩個情境（enable_he=True / False）
    - 顏色：plain / encrypted
    """
    # 以 enable_he=False 的 plain 欄位當作完整欄位集合
    all_features = list(protected_plain_only["plain"].keys())

    # 0 = plain, 1 = encrypted
    status_matrix = [[0] * len(all_features) for _ in range(2)]
    scenarios = ["enable_he=False", "enable_he=True"]

    # enable_he=True：記錄哪些欄位被加密
    encrypted_fields_he = set(protected_with_he["encrypted"].keys())
    for j, feat in enumerate(all_features):
        if feat in encrypted_fields_he:
            status_matrix[1][j] = 1

    fig, ax = plt.subplots(figsize=(0.8 * len(all_features) + 2, 4))

    cmap = {0: "#4CAF50", 1: "#F44336"}  # plain=綠色, encrypted=紅色

    for i in range(2):  # 兩種情境
        for j, feat in enumerate(all_features):
            val = status_matrix[i][j]
            ax.barh(
                y=i,
                width=1,
                left=j,
                color=cmap[val],
                edgecolor="black",
            )

    ax.set_yticks([0, 1])
    ax.set_yticklabels(scenarios)

    ax.set_xticks(range(len(all_features)))
    ax.set_xticklabels(all_features, rotation=45, ha="right")

    ax.set_xlim(0, len(all_features))
    ax.set_xlabel("Features")
    ax.set_title("Plain vs Encrypted Fields under Different HE Settings")

    # 圖例
    legend_elements = [
        Patch(facecolor=cmap[0], edgecolor="black", label="plain"),
        Patch(facecolor=cmap[1], edgecolor="black", label="encrypted"),
    ]
    ax.legend(handles=legend_elements, loc="upper right")

    plt.tight_layout()

    # 將圖檔存到 Week6 資料夾
    out_dir = Path(__file__).resolve().parent
    out_path = out_dir / "week6_mixed_protection_visualization.png"
    plt.savefig(out_path, dpi=200)
    plt.close(fig)

    print(f"[Visualization saved] {out_path}")


def summarize_structure_diff(
    protected_with_he: Dict[str, Dict[str, Any]],
    protected_plain_only: Dict[str, Dict[str, Any]],
) -> None:
    """
    印出一個表格，對照兩種設定下，每個欄位是屬於哪裡：
    - enable_he=False: 一律在 plain
    - enable_he=True: 有些在 plain、有些在 encrypted
    """
    # 蒐集所有欄位名稱
    fields = set(protected_plain_only["plain"].keys())
    fields.update(protected_with_he["plain"].keys())
    fields.update(protected_with_he["encrypted"].keys())
    fields = sorted(fields)

    rows = []
    for f in fields:
        row = {
            "field": f,
            "enable_he=False (location)": "plain" if f in protected_plain_only["plain"] else "-",
            "enable_he=True (location)": (
                "encrypted" if f in protected_with_he["encrypted"] else
                ("plain" if f in protected_with_he["plain"] else "-")
            ),
            "sample_value_when_he=False": protected_plain_only["plain"].get(f, ""),
            "sample_value_when_he=True_plain": protected_with_he["plain"].get(f, ""),
            "sample_value_when_he=True_encrypted": protected_with_he["encrypted"].get(f, ""),
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    print("=== 結構差異一覽表（per field）===")
    print(df.to_string(index=False))
    print()


def main() -> None:
    # 使用真實 Paillier HE encryptor；若未安裝 phe 會在此拋出明確錯誤
    encryptor = PaillierEncryptor()
    pipeline = MixedProtectionPipeline(encryptor=encryptor)

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

    # 3️⃣ 印出資料結構差異一覽表
    summarize_structure_diff(protected_with_he, protected_plain_only)

    # 4️⃣ 視覺化兩種情境下欄位狀態
    visualize_protection_result(protected_with_he, protected_plain_only)


if __name__ == "__main__":
    main()

