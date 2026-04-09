"""Tests for server_module.TrainedModelServer."""
from __future__ import annotations

import pytest
from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from server_module.server import TrainedModelServer, resolve_model_path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def encryptor():
    return CKKSEncryptor()


@pytest.fixture()
def server_from_model():
    """Load TrainedModelServer from the real lr_model.joblib."""
    return TrainedModelServer()


@pytest.fixture()
def server_from_weights():
    """Create TrainedModelServer with explicit weights for deterministic tests."""
    return TrainedModelServer.from_weights(
        weights={
            "session_duration": 0.5,
            "failed_attempts": 1.0,
            "behavioral_score": -0.3,
            "user_id": 0.0,
        },
        bias=-1.0,
    )


# ---------------------------------------------------------------------------
# Tests: Loading
# ---------------------------------------------------------------------------

def test_loads_weights_from_joblib(server_from_model):
    """Weights and bias should be extracted from the trained model."""
    assert isinstance(server_from_model.weights, dict)
    assert len(server_from_model.weights) > 0
    assert isinstance(server_from_model.bias, float)
    # The trained model has 4 features
    assert "session_duration" in server_from_model.weights
    assert "failed_attempts" in server_from_model.weights
    assert "behavioral_score" in server_from_model.weights
    assert "user_id" in server_from_model.weights


def test_from_weights_classmethod():
    """from_weights should create a server without loading a joblib file."""
    server = TrainedModelServer.from_weights(
        weights={"a": 1.0, "b": 2.0},
        bias=0.5,
    )
    assert server.weights == {"a": 1.0, "b": 2.0}
    assert server.bias == 0.5


# ---------------------------------------------------------------------------
# Tests: Plaintext inference
# ---------------------------------------------------------------------------

def test_infer_plain_only(server_from_weights):
    """Plaintext-only payload should return a float z."""
    payload = {
        "plain": {
            "session_duration": 2.0,
            "failed_attempts": 3.0,
            "behavioral_score": 10.0,
        },
        "encrypted": {},
    }
    z = server_from_weights.infer(payload)
    # z = -1.0 + 0.5*2.0 + 1.0*3.0 + (-0.3)*10.0 = -1.0 + 1.0 + 3.0 - 3.0 = 0.0
    assert isinstance(z, float)
    assert abs(z - 0.0) < 1e-6


def test_infer_unknown_fields_ignored(server_from_weights):
    """Fields not in weights should have weight 0 (ignored)."""
    payload = {
        "plain": {
            "session_duration": 2.0,
            "unknown_field": 9999.0,
        },
        "encrypted": {},
    }
    z = server_from_weights.infer(payload)
    # z = -1.0 + 0.5*2.0 + 0.0*9999.0 = 0.0
    assert abs(z - 0.0) < 1e-6


# ---------------------------------------------------------------------------
# Tests: Mixed (plain + encrypted) inference
# ---------------------------------------------------------------------------

def test_infer_mixed_payload_decrypts_correctly(server_from_weights, encryptor):
    """Mixed payload with Paillier encrypted fields should produce correct z after decryption."""
    enc_user_id = encryptor.encrypt(100.0)

    payload = {
        "plain": {
            "session_duration": 2.0,
            "failed_attempts": 3.0,
            "behavioral_score": 10.0,
        },
        "encrypted": {
            "user_id": enc_user_id,  # weight = 0.0
        },
    }
    z_enc = server_from_weights.infer(payload)

    # z_enc is a Paillier ciphertext. Decrypt to verify.
    z_plain = encryptor.decrypt(z_enc)
    # z = -1.0 + 0.5*2 + 1.0*3 + (-0.3)*10 + 0.0*100 = 0.0
    assert abs(z_plain - 0.0) < 0.1  # Paillier has some floating point noise


def test_infer_encrypted_with_nonzero_weight(encryptor):
    """Encrypted fields with nonzero weight should contribute to z."""
    server = TrainedModelServer.from_weights(
        weights={"x_plain": 1.0, "x_enc": 2.0},
        bias=0.0,
    )
    enc_val = encryptor.encrypt(3.0)

    payload = {
        "plain": {"x_plain": 5.0},
        "encrypted": {"x_enc": enc_val},
    }
    z_enc = server.infer(payload)
    z_decrypted = encryptor.decrypt(z_enc)
    # z = 0.0 + 1.0*5.0 + 2.0*3.0 = 11.0
    assert abs(z_decrypted - 11.0) < 0.1


# ---------------------------------------------------------------------------
# Tests: Real model inference sanity check
# ---------------------------------------------------------------------------

def test_real_model_infer_reasonable(server_from_model):
    """Inference with the real trained model weights should produce a reasonable z."""
    payload = {
        "plain": {
            "session_duration": 0.5,
            "failed_attempts": 0.3,
            "behavioral_score": 0.7,
        },
        "encrypted": {},
    }
    z = server_from_model.infer(payload)
    assert isinstance(z, float)
    # z should be a finite number, not NaN or Inf
    assert z == z  # not NaN
    assert abs(z) < 100  # reasonable range
