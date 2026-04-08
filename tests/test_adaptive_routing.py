from __future__ import annotations

import hashlib

from adaptive_routing.adaptive_router import AdaptiveRouter, RoutingConfig
from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from adaptive_routing.feature_encoder import SimpleRecordEncoder


class SensitivityStub:
    def __init__(self, *, encryption_required: bool, is_sensitive: bool, level: str = "LOW", risk: float = 0.0):
        self._res = {
            "encryption_required": encryption_required,
            "is_sensitive": is_sensitive,
            "sensitivity_level": level,
            "risk_score": risk,
        }

    def classify(self, record):
        return dict(self._res)


def _sample_raw_record():
    return {
        "user_id": "alice",
        "login_status": "Success",
        "ip_address": "192.168.1.14",
        "location": "Canada",
        "session_duration": 7.4,
        "failed_attempts": 0,
        "behavioral_score": 88.5,
        "timestamp": "2023-08-24 13:25:34",
        "device_type": "Desktop",
        "anomaly": 0,
    }


def test_encoder_uses_stable_hash():
    enc = SimpleRecordEncoder(hash_mod=10_000)
    out = enc.encode({"location": "Canada"})
    assert "location" in out
    expected = int(int.from_bytes(hashlib.sha256("Canada".encode("utf-8")).digest()[:8], "big") % 10_000)
    assert out["location"] == expected


def test_routing_high_must_use_he():
    router = AdaptiveRouter(
        config=RoutingConfig(latency_budget_ms=1.0, network_rtt_ms=30.0, prefer_he_on_medium=False),
        encryptor=CKKSEncryptor(),
        sensitivity_clf=SensitivityStub(encryption_required=True, is_sensitive=True, level="HIGH", risk=1.0),
        encoder=SimpleRecordEncoder(),
        threshold=0.5,
    )
    route, s = router.decide_route(_sample_raw_record())
    assert route == "server_mixed_he"
    assert s["sensitivity_level"] == "HIGH"


def test_routing_low_prefers_plain():
    router = AdaptiveRouter(
        config=RoutingConfig(),
        encryptor=CKKSEncryptor(),
        sensitivity_clf=SensitivityStub(encryption_required=False, is_sensitive=False, level="LOW", risk=0.0),
        encoder=SimpleRecordEncoder(),
    )
    route, s = router.decide_route(_sample_raw_record())
    assert route == "server_plain"
    assert s["sensitivity_level"] == "LOW"


def test_routing_medium_respects_latency_budget():
    raw = _sample_raw_record()

    # default estimates: plain ~= rtt(30)+10=40, he ~= rtt(30)+80=110
    router_plain = AdaptiveRouter(
        config=RoutingConfig(latency_budget_ms=100.0, network_rtt_ms=30.0, prefer_he_on_medium=True),
        encryptor=CKKSEncryptor(),
        sensitivity_clf=SensitivityStub(encryption_required=False, is_sensitive=True, level="MEDIUM", risk=0.5),
        encoder=SimpleRecordEncoder(),
    )
    route1, _ = router_plain.decide_route(raw)
    assert route1 == "server_plain"

    router_he = AdaptiveRouter(
        config=RoutingConfig(latency_budget_ms=120.0, network_rtt_ms=30.0, prefer_he_on_medium=True),
        encryptor=CKKSEncryptor(),
        sensitivity_clf=SensitivityStub(encryption_required=False, is_sensitive=True, level="MEDIUM", risk=0.5),
        encoder=SimpleRecordEncoder(),
    )
    route2, _ = router_he.decide_route(raw)
    assert route2 == "server_mixed_he"


def test_process_he_route_decrypts_when_encrypted_fields_exist():
    router = AdaptiveRouter(
        config=RoutingConfig(latency_budget_ms=999.0, network_rtt_ms=30.0, prefer_he_on_medium=True),
        encryptor=CKKSEncryptor(),
        sensitivity_clf=SensitivityStub(encryption_required=True, is_sensitive=True, level="HIGH", risk=1.0),
        encoder=SimpleRecordEncoder(),
        threshold=0.5,
    )
    result = router.process(_sample_raw_record())
    assert result["enable_he"] is True
    assert result["route"] == "server_mixed_he"
    assert result["payload_summary"]["encrypted_keys"]  # should not be empty for this record
    assert result["decrypted"] is True

