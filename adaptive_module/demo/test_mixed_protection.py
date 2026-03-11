from ckks_homomorphic_encryption.he_encryptor import PaillierEncryptor
from adaptive_module.core.mixed_protection import MixedProtectionPipeline

record = {
    "user_id": "user_1",
    "ip_address": "8.8.8.8",
    "location": "Mars",
    "session_duration": 1000,
    "failed_attempts": 3,
    "behavioral_score": 20
}

# 建立 encryptor
encryptor = PaillierEncryptor()
pipeline = MixedProtectionPipeline(encryptor=encryptor)

sensitive = pipeline.get_sensitive_fields(record)
print("sensitive fields:", sensitive)

payload = pipeline.protect_record(record, enable_he=True)

print("plain:", payload["plain"])
print("encrypted:", payload["encrypted"])