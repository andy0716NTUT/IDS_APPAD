"""Client-side HTTP proxy that implements ModelServerLike.

Drop-in replacement for LRModelServer — sends inference requests
to a remote Flask server instead of running locally.
"""
from __future__ import annotations

from typing import Any, Dict

import requests

from server_module.serialization import (
    deserialize_result,
    serialize_payload,
)


class RemoteInferenceError(RuntimeError):
    """Raised when the remote inference server returns an error."""


class RemoteLRModelServer:
    """ModelServerLike implementation that forwards to a remote server."""

    def __init__(
        self,
        base_url: str,
        ckks_context: Any = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.ckks_context = ckks_context
        self.timeout = timeout
        self._context_uploaded = False

    # -- Public context upload ------------------------------------------------

    def _ensure_context_uploaded(self) -> None:
        """Upload the public CKKS context to the server (once)."""
        if self._context_uploaded or self.ckks_context is None:
            return

        ctx_copy = self.ckks_context.copy()
        ctx_copy.make_context_public()
        raw = ctx_copy.serialize()

        resp = requests.post(
            f"{self.base_url}/context",
            data=raw,
            headers={"Content-Type": "application/octet-stream"},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RemoteInferenceError(
                f"Failed to upload CKKS context: {resp.status_code} {resp.text}"
            )
        self._context_uploaded = True

    # -- ModelServerLike interface --------------------------------------------

    def infer(self, payload: Dict[str, Dict[str, Any]]) -> Any:
        """Serialize payload, POST to /infer, deserialize result."""
        has_encrypted = bool(payload.get("encrypted"))

        if has_encrypted:
            self._ensure_context_uploaded()

        wire = serialize_payload(payload)

        resp = requests.post(
            f"{self.base_url}/infer",
            json=wire,
            timeout=self.timeout,
        )

        if resp.status_code != 200:
            raise RemoteInferenceError(
                f"Remote inference failed: {resp.status_code} {resp.text}"
            )

        result_data = resp.json()
        return deserialize_result(result_data, self.ckks_context)
