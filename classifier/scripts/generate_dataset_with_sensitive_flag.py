from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from classifier.core.classifier import SensitivityClassifier


COLUMN_MAPPING = {
    "User ID": "user_id",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
}


def row_to_record(row: pd.Series) -> dict:
    return {internal: row[csv] for csv, internal in COLUMN_MAPPING.items() if csv in row}


def resolve_default_input() -> Path:
    return ROOT / "dataset" / "synthetic_web_auth_logs.csv"


def resolve_default_output() -> Path:
    return ROOT / "dataset" / "synthetic_web_auth_logs_sensitive_flag.csv"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate dataset with sensitive encryption flag column")
    parser.add_argument("--input", type=str, default=str(resolve_default_input()))
    parser.add_argument("--output", type=str, default=str(resolve_default_output()))
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {input_path}")

    df = pd.read_csv(input_path)
    clf = SensitivityClassifier()

    # Sensitive traffic should be encrypted in this experiment.
    df["sensitive_needs_encryption"] = df.apply(
        lambda row: bool(clf.classify(row_to_record(row)).get("is_sensitive", False)),
        axis=1,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    total = int(len(df))
    sensitive_count = int(df["sensitive_needs_encryption"].sum()) if total > 0 else 0
    ratio = (sensitive_count / total) if total > 0 else 0.0

    print(f"Input : {input_path}")
    print(f"Output: {output_path}")
    print(f"Rows  : {total}")
    print(f"Sensitive rows requiring encryption: {sensitive_count}")
    print(f"Sensitive ratio: {ratio:.4f}")


if __name__ == "__main__":
    main()
