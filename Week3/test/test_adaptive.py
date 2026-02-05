from Week3.appad_core.adaptive_module import AdaptiveModule

adaptive = AdaptiveModule()

x = {
    "user_id": 123,
    "session_duration": 5.3,
    "failed_attempts": 4,
    "behavioral_score": 0.2
}

# Case 1：敏感
payload = adaptive.protect(
    x,
    flag=True,
    sensitive_idx=["failed_attempts", "behavioral_score"]
)

print("Sensitive Case:")
print(payload)

# Case 2：不敏感
payload = adaptive.protect(
    x,
    flag=False,
    sensitive_idx=[]
)

print("\nNon-sensitive Case:")
print(payload)
