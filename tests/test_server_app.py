"""Integration tests for the inference Flask server (server_module.server_app)."""
from __future__ import annotations

import json

import pytest
from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from server_module.serialization import serialize_payload, serialize_result
from server_module.server import TrainedModelServer
from server_module.server_app import app, create_app


@pytest.fixture(scope="module")
def encryptor():
    return CKKSEncryptor()


@pytest.fixture(scope="module")
def client():
    create_app()  # initialises the global _server
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


# ---------------------------------------------------------------------------
# Plaintext inference (no context required)
# ---------------------------------------------------------------------------

def test_infer_plain_only(client):
    payload = {"plain": {"session_duration": 0.5, "failed_attempts": 0.3}, "encrypted": {}}
    resp = client.post("/infer", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["type"] == "plain"
    assert isinstance(data["value"], float)


# ---------------------------------------------------------------------------
# Context upload + encrypted inference
# ---------------------------------------------------------------------------

def test_context_upload(client, encryptor):
    pub_bytes = encryptor.public_context_bytes()
    resp = client.post(
        "/context",
        data=pub_bytes,
        content_type="application/octet-stream",
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_infer_with_encrypted(client, encryptor):
    # Upload context first
    pub_bytes = encryptor.public_context_bytes()
    client.post("/context", data=pub_bytes, content_type="application/octet-stream")

    enc_val = encryptor.encrypt(0.5)
    payload = {
        "plain": {"session_duration": 0.5},
        "encrypted": {"user_id": enc_val},
    }
    wire = serialize_payload(payload)
    resp = client.post("/infer", json=wire)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["type"] == "encrypted"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_infer_encrypted_without_context():
    """Encrypted payload without context upload should return 400."""
    # Use a fresh app instance with no context
    import server_module.server_app as sa
    sa._ckks_context = None  # reset

    app.config["TESTING"] = True
    with app.test_client() as c:
        payload = {"plain": {}, "encrypted": {"x": "some_base64"}}
        resp = c.post("/infer", json=payload)
        assert resp.status_code == 400
        assert "context" in resp.get_json()["error"].lower()


def test_infer_no_json(client):
    resp = client.post("/infer", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_context_empty_body(client):
    resp = client.post("/context", data=b"", content_type="application/octet-stream")
    assert resp.status_code == 400
