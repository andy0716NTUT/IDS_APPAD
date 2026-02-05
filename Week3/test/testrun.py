from Week3.appad_core.core import APPADCore

if __name__ == "__main__":
    record = {
        "session_duration": 400,
        "failed_attempts": 4,
        "behavioral_score": 45,
        "ip_address": "8.8.8.8",
        "login_status": "failed",
        "location": "Germany"
    }

    appad = APPADCore()
    result = appad.process(record)

    print("APPAD Result:")
    print(result)
