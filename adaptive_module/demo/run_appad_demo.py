from adaptive_module.core.core import APPADCore


record = {
    "User ID": 1,
    "Session Duration": 1000,
    "Failed Attempts": 3,
    "Behavioral Score": 20
}

appad = APPADCore()

result = appad.process(record)

print("APPAD RESULT")
print("-------------------")
print("plaintext score :", result["plaintext_score"])
print("encrypted score :", result["encrypted_score"])
print("difference      :", result["difference"])
print("latency (ms)    :", result["latency_ms"])