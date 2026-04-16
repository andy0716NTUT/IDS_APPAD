"""Standalone Flask inference server.

Exposes the LRModelServer over HTTP so that Client and Server
can run as independent services.

Usage:
    py -3.12 server_module/server_app.py --port 5001
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

# Ensure project root is importable when running as __main__
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from server_module.serialization import (
    deserialize_payload,
    serialize_result,
)
from server_module.server import LRModelServer

app = Flask(__name__)

# -- App-level state --------------------------------------------------------
_server: LRModelServer | None = None
_ckks_context: Any = None  # public-key-only tenseal context


def _get_server() -> LRModelServer:
    assert _server is not None, "LRModelServer not initialised"
    return _server


# -- Endpoints --------------------------------------------------------------

@app.get("/health")
def health() -> Any:
    return jsonify({"ok": True})


@app.post("/context")
def upload_context() -> Any:
    """Receive the public CKKS context from the client (binary body)."""
    global _ckks_context

    raw = request.get_data()
    if not raw:
        return jsonify({"error": "Empty request body"}), 400

    try:
        import tenseal as ts  # type: ignore
        _ckks_context = ts.context_from(raw, n_threads=1)
    except Exception as exc:
        return jsonify({"error": f"Failed to load CKKS context: {exc}"}), 400

    return jsonify({"ok": True, "context_bytes": len(raw)})


@app.post("/infer")
def infer() -> Any:
    """Run inference on the received payload."""
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    has_encrypted = bool(body.get("encrypted"))

    if has_encrypted and _ckks_context is None:
        return jsonify({
            "error": "CKKS context not uploaded. POST to /context first.",
        }), 400

    try:
        payload = deserialize_payload(body, _ckks_context) if has_encrypted else {
            "plain": body.get("plain", {}),
            "encrypted": {},
        }
    except Exception as exc:
        return jsonify({"error": f"Payload deserialization failed: {exc}"}), 400

    try:
        z = _get_server().infer(payload)
    except Exception as exc:
        return jsonify({"error": f"Inference failed: {exc}"}), 500

    return jsonify(serialize_result(z))


# -- Bootstrap ---------------------------------------------------------------

def create_app(model_path: str | Path | None = None) -> Flask:
    """Factory for programmatic / test usage."""
    global _server
    _server = LRModelServer(model_path=Path(model_path) if model_path else None)
    return app


def main() -> None:
    global _server

    parser = argparse.ArgumentParser(description="IDS inference server")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--model-path",
        default=str(_PROJECT_ROOT / "logistic_regression_model" / "output_lr" / "lr_model.joblib"),
    )
    args = parser.parse_args()

    _server = LRModelServer(model_path=Path(args.model_path))
    print(f"Inference server starting on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
