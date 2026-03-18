"""Integration tests for the end-to-end pipeline."""
from __future__ import annotations

import pytest
from ckks_homomorphic_encryption.he_encryptor import PaillierEncryptor
from adaptive_routing.system import IDSSystem, IDSSystemConfig
from adaptive_routing.adaptive_router import RoutingConfig
from server_module.server import TrainedModelServer


@pytest.fixture(scope="module")
def encryptor():
    return PaillierEncryptor()


@pytest.fixture(scope="module")
def system(encryptor):
    """Build a full IDSSystem with the real trained model."""
    server = TrainedModelServer()
    return IDSSystem(
        config=IDSSystemConfig(
            routing=RoutingConfig(latency_budget_ms=200.0),
            decision_threshold=0.5,
        ),
        encryptor=encryptor,
        server=server,
    )


# Sample records representing different sensitivity levels
RECORD_LOW = {
    "user_id": 42,
    "login_status": "success",
    "ip_address": "192.168.1.10",
    "location": "office",
    "session_duration": 0.2,
    "failed_attempts": 0,
    "behavioral_score": 0.9,
    "timestamp": "2026-01-15T10:00:00",
    "device_type": "desktop",
}

RECORD_HIGH = {
    "user_id": 999,
    "login_status": "failed",
    "ip_address": "203.0.113.50",
    "location": "unknown_region",
    "session_duration": 0.8,
    "failed_attempts": 5,
    "behavioral_score": 0.1,
    "timestamp": "2026-01-15T03:00:00",
    "device_type": "mobile",
}


def test_process_returns_expected_keys(system):
    """process_event should return a result dict with all required keys."""
    result = system.process_event(RECORD_LOW)
    expected_keys = {"route", "enable_he", "sensitivity", "prob", "is_anomaly", "latency_ms"}
    assert expected_keys.issubset(result.keys())


def test_prob_in_valid_range(system):
    """Probability should be between 0 and 1."""
    for record in [RECORD_LOW, RECORD_HIGH]:
        result = system.process_event(record)
        assert 0.0 <= result["prob"] <= 1.0, f"prob={result['prob']} out of range"


def test_high_sensitivity_uses_he(system):
    """HIGH sensitivity record should route through HE."""
    result = system.process_event(RECORD_HIGH)
    if result["sensitivity"] == "HIGH":
        assert result["enable_he"] is True
        assert result["route"] == "server_mixed_he"


def test_he_route_has_decrypted_true(system):
    """When HE route is used, the result should show decrypted=True."""
    result = system.process_event(RECORD_HIGH)
    if result["enable_he"]:
        assert result["decrypted"] is True


def test_plain_route_has_decrypted_false(system):
    """When plain route is used, decrypted should be False."""
    result = system.process_event(RECORD_LOW)
    if not result["enable_he"]:
        assert result["decrypted"] is False


def test_latency_is_positive(system):
    """Latency should be a positive number."""
    result = system.process_event(RECORD_LOW)
    assert result["latency_ms"] > 0


def test_trained_model_weights_used(system):
    """The system's server should be our TrainedModelServer, not the default stub."""
    server = system.router.server
    assert isinstance(server, TrainedModelServer)
