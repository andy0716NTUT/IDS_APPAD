import time
from Week6.mixed_protection import MixedProtectionPipeline
record = {
    "user_id": 101,
    "ip_address": 12345,
    "session_duration": 15,
    "failed_attempts": 2,
    "behavioral_score": 0.82
}

pipeline = MixedProtectionPipeline()

print("\n==============================")
print("Case Study: enable_he = True")
print("==============================")

start = time.time()
result_he = pipeline.protect_record(record, enable_he=True)
end = time.time()

print("\n[Protected Record]")
print(result_he)

print("\nLatency:", round((end - start)*1000, 3), "ms")


print("\n==============================")
print("Case Study: enable_he = False")
print("==============================")

start = time.time()
result_plain = pipeline.protect_record(record, enable_he=False)
end = time.time()

print("\n[Protected Record]")
print(result_plain)

print("\nLatency:", round((end - start)*1000, 3), "ms")