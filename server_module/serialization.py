"""Serialization utilities for CKKS payloads over HTTP.

Converts between in-memory tenseal objects and JSON-safe wire format:
- Plain fields: passed as-is (float values)
- Encrypted fields: CKKSVector → base64-encoded serialized bytes
"""
from __future__ import annotations

import base64
from typing import Any


def _is_ckks_vector(obj: Any) -> bool:
    return hasattr(obj, "serialize") and callable(obj.serialize)


# ---------------------------------------------------------------------------
# Payload serialization (client → server)
# ---------------------------------------------------------------------------

def serialize_payload(payload: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Convert in-memory payload to JSON-safe wire format.

    Input:  {"plain": {k: float}, "encrypted": {k: CKKSVector}}
    Output: {"plain": {k: float}, "encrypted": {k: base64_str}}
    """
    plain = {k: float(v) for k, v in payload.get("plain", {}).items()}
    encrypted: dict[str, str] = {}
    for k, v in payload.get("encrypted", {}).items():
        if _is_ckks_vector(v):
            encrypted[k] = base64.b64encode(v.serialize()).decode("ascii")
        else:
            raise TypeError(f"Cannot serialize encrypted field '{k}': {type(v)}")
    return {"plain": plain, "encrypted": encrypted}


def deserialize_payload(
    data: dict[str, Any],
    ckks_context: Any,
) -> dict[str, dict[str, Any]]:
    """Convert wire-format payload back to in-memory objects.

    Requires a tenseal CKKS context (public-key only is sufficient)
    to reconstruct CKKSVector objects.
    """
    import tenseal as ts  # type: ignore

    plain = data.get("plain", {})
    encrypted: dict[str, Any] = {}
    for k, v in data.get("encrypted", {}).items():
        raw_bytes = base64.b64decode(v)
        encrypted[k] = ts.ckks_vector_from(ckks_context, raw_bytes)
    return {"plain": plain, "encrypted": encrypted}


# ---------------------------------------------------------------------------
# Result serialization (server → client)
# ---------------------------------------------------------------------------

def serialize_result(z: Any) -> dict[str, Any]:
    """Serialize inference result (float or CKKSVector) for HTTP response."""
    if _is_ckks_vector(z):
        return {
            "type": "encrypted",
            "value": base64.b64encode(z.serialize()).decode("ascii"),
        }
    return {"type": "plain", "value": float(z)}


def deserialize_result(data: dict[str, Any], ckks_context: Any) -> Any:
    """Deserialize inference result from HTTP response."""
    if data["type"] == "encrypted":
        import tenseal as ts  # type: ignore

        raw_bytes = base64.b64decode(data["value"])
        return ts.ckks_vector_from(ckks_context, raw_bytes)
    return float(data["value"])
