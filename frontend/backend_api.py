from __future__ import annotations

import json
import os
import subprocess
import sys
import csv
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output_results"
PLOTS_DIR = OUTPUT_DIR / "privacy_ratio_plots"
MODEL_PATH = ROOT / "logistic_regression_model" / "output_lr" / "lr_model.joblib"
MAIN_PATH = ROOT / "main.py"
DEFAULT_PIPELINE_DATASET = ROOT / "data_preprocessing" / "output" / "normalize" / "test_normalized.csv"
MAX_PREVIEW_ROWS = 50
MAX_LISTED_CIPHERTEXT_FILES = 200
DEFAULT_HEX_PAGE_BYTES = 512
MAX_PREVIEW_ROWS_HARD_CAP = 2000

# Remote inference server URL (set via --server-url CLI flag or INFERENCE_SERVER_URL env var)
INFERENCE_SERVER_URL: str | None = None


def _safe_output_file(path_text: str) -> Path:
    candidate = (ROOT / path_text).resolve()
    if not str(candidate).startswith(str(ROOT.resolve())):
        raise ValueError("Invalid path")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(str(candidate))
    return candidate


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _to_workspace_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")
    except Exception:
        return str(path)


def _to_bool_like(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value) != 0.0
    text = str(value).strip().lower()
    return text in {"1", "true", "t", "yes", "y", "sensitive", "high", "medium"}


def _format_hex_dump(payload: bytes, base_offset: int) -> str:
    lines: list[str] = []
    for idx in range(0, len(payload), 16):
        chunk = payload[idx : idx + 16]
        offset = base_offset + idx
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_bytes = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hex_bytes:<47}  {ascii_bytes}")
    return "\n".join(lines)


def _extract_failure_reason(stderr_text: str, fallback: str = "main.py execution failed") -> str:
    lines = [line.strip() for line in (stderr_text or "").splitlines() if line.strip()]
    if not lines:
        return fallback

    for line in reversed(lines):
        if "Feature scale consistency check failed" in line:
            return line

    for line in reversed(lines):
        if line.startswith("ValueError:"):
            return line

    return lines[-1]


def _load_sampled_plain_preview(path_text: str | None, max_rows: int = MAX_PREVIEW_ROWS) -> list[dict[str, Any]]:
    if not path_text:
        return []

    csv_path = (ROOT / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text)
    if not csv_path.exists():
        return []

    preview: list[dict[str, Any]] = []
    effective_max_rows = max(1, min(int(max_rows), MAX_PREVIEW_ROWS_HARD_CAP))
    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        for idx, row in enumerate(reader):
            if idx >= effective_max_rows:
                break
            preview.append(
                {
                    "sample_idx": int(_to_float(row.get("sample_idx"), idx)),
                    "pre_sensitive_label": row.get("pre_sensitive_label") or ("敏感" if _to_bool_like(row.get("sensitive_needs_encryption")) else "非敏感"),
                    "anomaly": int(_to_float(row.get("Anomaly"), 0)),
                    "user_id": row.get("User ID"),
                    "login_status": row.get("Login Status"),
                    "location": row.get("Location"),
                }
            )
    return preview


def _list_ciphertext_files(dir_text: str | None) -> dict[str, Any]:
    if not dir_text:
        return {"files": [], "total": 0}

    dir_path = (ROOT / dir_text).resolve() if not Path(dir_text).is_absolute() else Path(dir_text)
    if not dir_path.exists() or not dir_path.is_dir():
        return {"files": [], "total": 0}

    all_files = sorted([p for p in dir_path.glob("*.bin") if p.is_file()])
    listed = [
        {
            "name": p.name,
            "path": _to_workspace_relative(p),
            "bytes": int(p.stat().st_size),
        }
        for p in all_files[:MAX_LISTED_CIPHERTEXT_FILES]
    ]
    return {"files": listed, "total": int(len(all_files))}


def _load_chart_series() -> dict[str, list[dict[str, float]]]:
    csv_path = PLOTS_DIR / "appad_metrics_vs_privacy_ratio.csv"
    if not csv_path.exists():
        return {
            "accuracy": [],
            "latency": [],
            "informationLeakage": [],
            "detectionEfficiency": [],
        }

    accuracy: list[dict[str, float]] = []
    latency: list[dict[str, float]] = []
    info_leakage: list[dict[str, float]] = []
    detection_eff: list[dict[str, float]] = []

    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        for row in reader:
            ratio = _to_float(row.get("privacy_sensitive_data_ratio"))
            accuracy.append({"ratio": ratio, "value": _to_float(row.get("accuracy"))})
            latency.append({"ratio": ratio, "value": _to_float(row.get("latency_sec"))})
            info_leakage.append({"ratio": ratio, "value": _to_float(row.get("information_leakage"))})
            detection_eff.append({"ratio": ratio, "value": _to_float(row.get("detection_efficiency"))})

    return {
        "accuracy": accuracy,
        "latency": latency,
        "informationLeakage": info_leakage,
        "detectionEfficiency": detection_eff,
    }


def _build_results_payload(mode: str) -> dict[str, Any]:
    metrics_path = OUTPUT_DIR / f"appad_main_metrics_{mode}.json"
    metrics = _load_json(metrics_path)
    chart_series = _load_chart_series()
    config = metrics.get("config", {}) if isinstance(metrics, dict) else {}

    sampled_plain_path = config.get("sampled_plain_data_path")
    encrypted_payload_path = config.get("pre_inference_encrypted_payload_path")
    encrypted_ciphertext_dir = config.get("pre_inference_encrypted_ciphertext_dir")
    preview_limit = int(config.get("sample_size_actual", MAX_PREVIEW_ROWS))

    ciphertext_files = _list_ciphertext_files(encrypted_ciphertext_dir)
    sampled_preview = _load_sampled_plain_preview(sampled_plain_path, max_rows=preview_limit)

    return {
        "mode": mode,
        "metrics": metrics,
        "chartSeries": chart_series,
        "artifacts": {
            "datasetPath": config.get("dataset_path", ""),
            "sampledPlainDataPath": sampled_plain_path or "",
            "encryptedPayloadIndexPath": encrypted_payload_path or "",
            "encryptedCiphertextDir": encrypted_ciphertext_dir or "",
            "encryptedCiphertextFiles": ciphertext_files["files"],
            "encryptedCiphertextFileCount": ciphertext_files["total"],
        },
        "sampledRecordsPreview": sampled_preview,
    }


app = Flask(__name__)
API_BUILD = "2026-04-16-consistency-guard-v3"


@app.get("/api/health")
def health() -> Any:
    return jsonify({"ok": True, "build": API_BUILD})


@app.get("/api/server-info")
def server_info() -> Any:
    """Return the current inference server configuration."""
    return jsonify({
        "serverUrl": INFERENCE_SERVER_URL,
        "mode": "remote" if INFERENCE_SERVER_URL else "local",
    })


@app.get("/api/results")
def results() -> Any:
    mode = request.args.get("mode", "mixed")
    payload = _build_results_payload(mode)
    if not payload["metrics"]:
        return jsonify({"error": "No metrics found. Please run analysis first."}), 404
    return jsonify(payload)


@app.post("/api/run")
def run_main() -> Any:
    body = request.get_json(silent=True) or {}
    mode = str(body.get("inferenceMode", "mixed"))
    seed = int(body.get("seed", 42))
    sample_size = int(body.get("sampleSize", 500))
    run_sweep = bool(body.get("runPrivacySweep", False))
    dataset_path = str(body.get("datasetPath", "")).strip()

    if mode not in {"plaintext", "ckks", "mixed"}:
        return jsonify({"error": "Invalid inference mode"}), 400

    if not MODEL_PATH.exists():
        return jsonify(
            {
                "error": "Model file not found. Please run training first.",
                "modelPath": str(MODEL_PATH),
            }
        ), 400

    # Allow per-request server-url override from frontend, fall back to global setting
    server_url = str(body.get("serverUrl", "")).strip() or INFERENCE_SERVER_URL

    cmd = [
        sys.executable,
        str(MAIN_PATH),
        "--pipeline",
        "--inference-mode",
        mode,
        "--sample-size",
        str(sample_size),
        "--seed",
        str(seed),
        "--model-path",
        str(MODEL_PATH),
    ]

    effective_dataset_path = dataset_path
    if not effective_dataset_path and DEFAULT_PIPELINE_DATASET.exists():
        effective_dataset_path = str(DEFAULT_PIPELINE_DATASET)

    if effective_dataset_path:
        cmd.extend(["--dataset-path", effective_dataset_path])

    if server_url:
        cmd += ["--server-url", server_url]

    if not run_sweep:
        cmd.append("--skip-privacy-ratio-sweep")

    # Ensure child Python process emits UTF-8 so Chinese logs are not garbled on Windows.
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    completed = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if completed.returncode != 0:
        reason = _extract_failure_reason(completed.stderr)
        return jsonify(
            {
                "error": reason,
                "errorSummary": "main.py execution failed",
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            }
        ), 500

    payload = _build_results_payload(mode)
    payload["stdout"] = completed.stdout
    return jsonify(payload)


@app.get("/api/files/<path:file_path>")
def files(file_path: str) -> Any:
    try:
        safe_file = _safe_output_file(file_path)
        return send_file(str(safe_file))
    except Exception:
        return jsonify({"error": "File not found"}), 404


@app.get("/api/ciphertext/hex")
def ciphertext_hex() -> Any:
    file_path = request.args.get("path", "")
    if not file_path:
        return jsonify({"error": "Missing path"}), 400

    offset = max(0, _to_int(request.args.get("offset"), 0))
    length = _to_int(request.args.get("length"), DEFAULT_HEX_PAGE_BYTES)
    length = min(max(64, length), 4096)

    try:
        safe_file = _safe_output_file(file_path)
    except Exception:
        return jsonify({"error": "File not found"}), 404

    file_size = int(safe_file.stat().st_size)
    if offset >= file_size:
        offset = max(0, file_size - length)

    with safe_file.open("rb") as fp:
        fp.seek(offset)
        payload = fp.read(length)

    hex_dump = _format_hex_dump(payload, offset)
    next_offset = offset + len(payload)

    return jsonify(
        {
            "path": _to_workspace_relative(safe_file),
            "totalBytes": file_size,
            "offset": offset,
            "length": int(len(payload)),
            "requestedLength": length,
            "nextOffset": next_offset,
            "prevOffset": max(0, offset - length),
            "hasPrev": offset > 0,
            "hasNext": next_offset < file_size,
            "hexDump": hex_dump,
        }
    )


if __name__ == "__main__":
    import argparse as _ap

    _parser = _ap.ArgumentParser(description="IDS frontend backend API")
    _parser.add_argument("--port", type=int, default=8000)
    _parser.add_argument("--host", default="127.0.0.1")
    _parser.add_argument(
        "--server-url",
        default=os.environ.get("INFERENCE_SERVER_URL"),
        help="Remote inference server URL (e.g. http://lacedore.org:6789)",
    )
    _args = _parser.parse_args()

    if _args.server_url:
        INFERENCE_SERVER_URL = _args.server_url
        print(f"Remote inference server: {INFERENCE_SERVER_URL}")
    else:
        print("Running in local inference mode")

    app.run(host=_args.host, port=_args.port, debug=False)
