from __future__ import annotations

import math

from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from decision_module.client_decision import ClientDecision, DecisionResult


def _make_decision(threshold: float = 0.5) -> ClientDecision:
    return ClientDecision(encryptor=CKKSEncryptor(), threshold=threshold)


# --- sigmoid ---

def test_sigmoid_zero():
    assert ClientDecision.sigmoid(0.0) == 0.5


def test_sigmoid_large_positive():
    assert ClientDecision.sigmoid(100.0) > 0.99


def test_sigmoid_large_negative():
    assert ClientDecision.sigmoid(-100.0) < 0.01


# --- decrypt_if_needed (plain path) ---

def test_plain_path_no_decrypt():
    cd = _make_decision()
    payload = {"plain": {"a": 1.0}, "encrypted": {}}
    z_plain, decrypted = cd.decrypt_if_needed(2.0, payload, enable_he=False)
    assert z_plain == 2.0
    assert decrypted is False


# --- decrypt_if_needed (HE path) ---

def test_he_path_decrypts():
    enc = CKKSEncryptor()
    cd = ClientDecision(encryptor=enc, threshold=0.5)

    original = 3.14
    ct = enc.encrypt(original)
    payload = {"plain": {}, "encrypted": {"ip_address": ct}}

    z_plain, decrypted = cd.decrypt_if_needed(ct, payload, enable_he=True)
    assert decrypted is True
    assert abs(z_plain - original) < 1e-6


# --- decide (full pipeline) ---

def test_decide_plain_above_threshold():
    cd = _make_decision(threshold=0.5)
    payload = {"plain": {"x": 1.0}, "encrypted": {}}
    result = cd.decide(z=2.0, payload=payload, enable_he=False)

    assert isinstance(result, DecisionResult)
    assert result.decrypted is False
    assert result.z_plain == 2.0
    expected_prob = 1.0 / (1.0 + math.exp(-2.0))
    assert abs(result.prob - expected_prob) < 1e-9
    assert result.is_anomaly is True  # prob ~0.88 > 0.5


def test_decide_plain_below_threshold():
    cd = _make_decision(threshold=0.5)
    payload = {"plain": {"x": 1.0}, "encrypted": {}}
    result = cd.decide(z=-2.0, payload=payload, enable_he=False)

    assert result.is_anomaly is False  # prob ~0.12 < 0.5
    assert result.decrypted is False


def test_decide_he_route_decrypts_and_decides():
    enc = CKKSEncryptor()
    cd = ClientDecision(encryptor=enc, threshold=0.5)

    z_value = 1.5
    ct = enc.encrypt(z_value)
    payload = {"plain": {"a": 0.1}, "encrypted": {"ip_address": ct}}

    result = cd.decide(z=ct, payload=payload, enable_he=True)

    assert result.decrypted is True
    assert abs(result.z_plain - z_value) < 1e-6
    expected_prob = 1.0 / (1.0 + math.exp(-z_value))
    assert abs(result.prob - expected_prob) < 1e-6
    assert result.is_anomaly is True  # prob ~0.82 > 0.5


def test_decide_threshold_boundary():
    cd = _make_decision(threshold=0.5)
    payload = {"plain": {"x": 1.0}, "encrypted": {}}
    # z=0 -> sigmoid=0.5, NOT > 0.5, so is_anomaly=False
    result = cd.decide(z=0.0, payload=payload, enable_he=False)
    assert result.prob == 0.5
    assert result.is_anomaly is False
