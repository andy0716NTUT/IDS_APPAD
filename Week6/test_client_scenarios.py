from Week6.mixed_protection import MixedProtectionPipeline


def run_scenarios():
    print("\n=== Client Side Scenario Test ===")

    pipeline = MixedProtectionPipeline()

    scenarios = {
        "Normal Login": {
            "user_id": 689,
            "ip_address": "192.168.1.14",
            "login_status": "Success",
            "location": "Canada",
            "session_duration": 7.4,
            "failed_attempts": 0,
            "behavioral_score": 88.5,
            "timestamp": "2023-08-24 13:25:34",
            "device_type": "Desktop",
            "anomaly": 0,
        },
        "Suspicious Login": {
            "user_id": 110,
            "ip_address": "8.8.8.8",
            "login_status": "Failed",
            "location": "Mars",
            "session_duration": 900,
            "failed_attempts": 4,
            "behavioral_score": 45.0,
            "timestamp": "2023-08-24 13:28:34",
            "device_type": "Mobile",
            "anomaly": 1,
        },
    }

    for name, record in scenarios.items():
        print(f"\n[Scenario] {name}")

        result = pipeline.protect_record(record, enable_he=True)

        print("Plain fields:", list(result["plain"].keys()))
        print("Encrypted fields:", list(result["encrypted"].keys()))


if __name__ == "__main__":
    run_scenarios()