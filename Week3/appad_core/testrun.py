from Week3.appad_core.core import APPADCore

if __name__ == "__main__":
    sample_record = {
        "ip_address": "8.8.8.8",
        "failed_attempts": 4,
        "behavioral_score": 0.45,
        "anomaly": 1
    }

    appad = APPADCore()
    result = appad.process(sample_record)

    print("APPAD Result:")
    print(result)
