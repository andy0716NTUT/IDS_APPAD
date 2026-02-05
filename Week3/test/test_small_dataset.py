import pandas as pd
from Week3.appad_core.core import APPADCore

def row_to_record(row):
    return {
        "session_duration": row["Session Duration"],
        "failed_attempts": row["Failed Attempts"],
        "behavioral_score": row["Behavioral Score"],
        "anomaly": row["Anomaly"],
    }

if __name__ == "__main__":
    df = pd.read_csv("dataset/synthetic_web_auth_logs.csv")

    appad = APPADCore()

    for i, row in df.head(20).iterrows():
        record = row_to_record(row)
        result = appad.process(record)

        print(f"[{i}] {result}")
