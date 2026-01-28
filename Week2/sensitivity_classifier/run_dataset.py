from pathlib import Path
import pandas as pd
from classifier import SensitivityClassifier

COLUMN_MAPPING = {
    "User ID": "user_id",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score"
}

def row_to_record(row):
    return {internal: row[csv] for csv, internal in COLUMN_MAPPING.items()}

def main():
    BASE_DIR = Path(__file__).resolve().parents[2]
    DATASET_PATH = BASE_DIR / "dataset" / "synthetic_web_auth_logs.csv"

    df = pd.read_csv(DATASET_PATH)

    clf = SensitivityClassifier()
    sensitive_count = 0
    high_count = 0
    level_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}

    for idx, row in df.iterrows():
        record = row_to_record(row)
        result = clf.classify(record)

        level = result.get("sensitivity_level", "LOW")
        level_counts[level] = level_counts.get(level, 0) + 1

        if result.get("is_sensitive"):
            sensitive_count += 1
        if level == "HIGH":
            high_count += 1

        reasons = ",".join(result.get("reasons", [])) or "-"
        print(
            f"[{idx:05d}] level={level:<6} score={result.get('risk_score', 0):>4} "
            f"encrypt={str(result.get('encryption_required', False)):<5} reasons={reasons}"
        )

    print("\nSummary:")
    print(f"Total records: {len(df)}")
    print(f"Sensitive records (MEDIUM/HIGH): {sensitive_count}")
    print(f"Sensitive ratio: {sensitive_count / len(df):.2f}")
    print(f"HIGH records: {high_count}")
    print(f"LOW records: {level_counts.get('LOW', 0)}")
    print(f"MEDIUM records: {level_counts.get('MEDIUM', 0)}")

if __name__ == "__main__":
    main()
