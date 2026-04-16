"""Tests for server_module.serialization round-trip correctness."""
from __future__ import annotations

import pytest
from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from server_module.serialization import (
    deserialize_payload,
    deserialize_result,
    serialize_payload,
    serialize_result,
)


@pytest.fixture(scope="module")
def encryptor():
    return CKKSEncryptor()


# ---------------------------------------------------------------------------
# Payload round-trip
# ---------------------------------------------------------------------------

def test_serialize_plain_only():
    payload = {"plain": {"a": 1.0, "b": 2.5}, "encrypted": {}}
    wire = serialize_payload(payload)
    assert wire["plain"] == {"a": 1.0, "b": 2.5}
    assert wire["encrypted"] == {}


def test_payload_round_trip_with_encrypted(encryptor):
    enc_val = encryptor.encrypt(42.0)
    payload = {
        "plain": {"x": 1.0},
        "encrypted": {"secret": enc_val},
    }

    wire = serialize_payload(payload)
    assert isinstance(wire["encrypted"]["secret"], str)  # base64 string

    restored = deserialize_payload(wire, encryptor.context)
    assert restored["plain"]["x"] == 1.0

    decrypted = encryptor.decrypt(restored["encrypted"]["secret"])
    assert abs(decrypted - 42.0) < 0.01


def test_payload_round_trip_empty_encrypted(encryptor):
    payload = {"plain": {"a": 5.0}, "encrypted": {}}
    wire = serialize_payload(payload)
    restored = deserialize_payload(wire, encryptor.context)
    assert restored["plain"]["a"] == 5.0
    assert restored["encrypted"] == {}


# ---------------------------------------------------------------------------
# Result round-trip
# ---------------------------------------------------------------------------

def test_result_round_trip_plain():
    result = serialize_result(3.14)
    assert result == {"type": "plain", "value": 3.14}
    restored = deserialize_result(result, None)
    assert abs(restored - 3.14) < 1e-9


def test_result_round_trip_encrypted(encryptor):
    enc = encryptor.encrypt(7.5)
    wire = serialize_result(enc)
    assert wire["type"] == "encrypted"
    assert isinstance(wire["value"], str)

    restored = deserialize_result(wire, encryptor.context)
    decrypted = encryptor.decrypt(restored)
    assert abs(decrypted - 7.5) < 0.01


# ---------------------------------------------------------------------------
# Public context export
# ---------------------------------------------------------------------------

def test_public_context_cannot_decrypt(encryptor):
    """A public-only context should NOT be able to decrypt ciphertexts."""
    import tenseal as ts

    pub_bytes = encryptor.public_context_bytes()
    pub_ctx = ts.context_from(pub_bytes, n_threads=1)

    enc = encryptor.encrypt(99.0)
    serialized = enc.serialize()
    restored = ts.ckks_vector_from(pub_ctx, serialized)

    with pytest.raises(Exception):
        restored.decrypt()
