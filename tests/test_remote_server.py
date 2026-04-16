"""Tests for server_module.remote_server.RemoteLRModelServer."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
from server_module.remote_server import RemoteInferenceError, RemoteLRModelServer


@pytest.fixture(scope="module")
def encryptor():
    return CKKSEncryptor()


# ---------------------------------------------------------------------------
# Plaintext inference (no context upload needed)
# ---------------------------------------------------------------------------

def test_infer_plain_posts_to_server():
    """Plain-only payload should POST to /infer and return a float."""
    remote = RemoteLRModelServer(base_url="http://fake:5001")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"type": "plain", "value": 1.23}

    with patch("server_module.remote_server.requests.post", return_value=mock_resp) as mock_post:
        z = remote.infer({"plain": {"x": 1.0}, "encrypted": {}})

    assert abs(z - 1.23) < 1e-9
    mock_post.assert_called_once()
    call_url = mock_post.call_args[0][0]
    assert call_url == "http://fake:5001/infer"


# ---------------------------------------------------------------------------
# Context upload
# ---------------------------------------------------------------------------

def test_context_uploaded_once(encryptor):
    """Context should be uploaded exactly once, on first encrypted inference."""
    remote = RemoteLRModelServer(
        base_url="http://fake:5001",
        ckks_context=encryptor.context,
    )

    mock_ctx_resp = MagicMock(status_code=200)
    mock_infer_resp = MagicMock(status_code=200)
    mock_infer_resp.json.return_value = {"type": "plain", "value": 0.0}

    enc_val = encryptor.encrypt(1.0)

    with patch("server_module.remote_server.requests.post") as mock_post:
        mock_post.side_effect = [mock_ctx_resp, mock_infer_resp, mock_infer_resp]

        # First call with encrypted: should upload context + infer
        remote.infer({"plain": {}, "encrypted": {"a": enc_val}})
        assert mock_post.call_count == 2  # context + infer

        # Second call: should NOT re-upload context
        remote.infer({"plain": {}, "encrypted": {"a": enc_val}})
        assert mock_post.call_count == 3  # only infer added


def test_plain_inference_skips_context_upload(encryptor):
    """Plain-only payloads should never trigger context upload."""
    remote = RemoteLRModelServer(
        base_url="http://fake:5001",
        ckks_context=encryptor.context,
    )

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"type": "plain", "value": 0.0}

    with patch("server_module.remote_server.requests.post", return_value=mock_resp) as mock_post:
        remote.infer({"plain": {"x": 1.0}, "encrypted": {}})
        assert mock_post.call_count == 1
        assert "/infer" in mock_post.call_args[0][0]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_infer_server_error_raises():
    """Non-200 response from /infer should raise RemoteInferenceError."""
    remote = RemoteLRModelServer(base_url="http://fake:5001")

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    with patch("server_module.remote_server.requests.post", return_value=mock_resp):
        with pytest.raises(RemoteInferenceError, match="500"):
            remote.infer({"plain": {"x": 1.0}, "encrypted": {}})


def test_context_upload_failure_raises(encryptor):
    """Failed context upload should raise RemoteInferenceError."""
    remote = RemoteLRModelServer(
        base_url="http://fake:5001",
        ckks_context=encryptor.context,
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "Bad request"

    enc_val = encryptor.encrypt(1.0)

    with patch("server_module.remote_server.requests.post", return_value=mock_resp):
        with pytest.raises(RemoteInferenceError, match="context"):
            remote.infer({"plain": {}, "encrypted": {"a": enc_val}})
