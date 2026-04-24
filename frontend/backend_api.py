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

# Ensure project root is importable for demo endpoint
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
OUTPUT_DIR = ROOT / "output_results"
PLOTS_DIR = OUTPUT_DIR / "privacy_ratio_plots"
MODEL_PATH = ROOT / "logistic_regression_model" / "output_lr" / "lr_model.joblib"
MAIN_PATH = ROOT / "main.py"

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


def _to_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


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

    return {
        "mode": mode,
        "metrics": metrics,
        "chartSeries": chart_series,
    }


def _ckks_preview(ciphertext: Any) -> dict[str, Any]:
    """Generate a preview of a CKKS ciphertext for frontend display."""
    import base64

    raw = ciphertext.serialize()
    b64 = base64.b64encode(raw).decode("ascii")
    return {
        "size_bytes": len(raw),
        "base64_preview": b64[:80] + "..." if len(b64) > 80 else b64,
        "base64_full": b64,
    }


app = Flask(__name__)


@app.get("/api/health")
def health() -> Any:
    return jsonify({"ok": True})


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
    run_sweep = bool(body.get("runPrivacySweep", False))

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
        "--seed",
        str(seed),
        "--model-path",
        str(MODEL_PATH),
    ]
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
        return jsonify(
            {
                "error": "main.py execution failed",
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            }
        ), 500

    payload = _build_results_payload(mode)
    payload["stdout"] = completed.stdout
    return jsonify(payload)


@app.post("/api/demo")
def demo_single_record() -> Any:
    """Process a single record through the full pipeline, returning every intermediate step."""
    import time as _time

    body = request.get_json(silent=True) or {}
    mode = str(body.get("inferenceMode", "mixed"))
    record = body.get("record")

    if mode not in {"plaintext", "ckks", "mixed"}:
        return jsonify({"error": "Invalid inference mode"}), 400

    # Lazy imports — only loaded when this endpoint is hit
    from classifier.core.classifier import SensitivityClassifier
    from classifier.core.feature_sensitivity import FeatureSensitivityClassifier
    from adaptive_routing.feature_encoder import SimpleRecordEncoder
    from adaptive_module.core.adaptive_module import AdaptiveModule
    from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
    from decision_module.client_decision import ClientDecision

    # Use a sample record if none provided
    if not record:
        import pandas as pd

        dataset_path = ROOT / "data_preprocessing" / "output" / "normalize" / "test_normalized.csv"
        if not dataset_path.exists():
            dataset_path = ROOT / "dataset" / "synthetic_web_auth_logs.csv"
        df = pd.read_csv(dataset_path)
        sample = df.sample(n=1, random_state=int(body.get("seed", 42))).iloc[0]
        record = {col: (v.item() if hasattr(v, "item") else v) for col, v in sample.items()}

    # Convert CSV column names to internal names for classifier compatibility
    from pipeline.appad_pipeline import CSV_TO_INTERNAL
    raw_display = dict(record)  # keep original for display
    internal_record = {CSV_TO_INTERNAL.get(k, k): v for k, v in record.items()}
    # Use internal names for all downstream processing
    record = internal_record

    # --- Step 1: Sensitivity classification ---
    t0 = _time.perf_counter()
    classifier = SensitivityClassifier()
    sensitivity = classifier.classify(record)
    t_classify = _time.perf_counter() - t0

    # --- Step 2: Feature-level sensitivity ---
    feat_clf = FeatureSensitivityClassifier()
    sensitive_fields = feat_clf.sensitive_indices(record, sensitivity.get("sensitivity_level"))

    # --- Step 3: Encode ---
    encoder = SimpleRecordEncoder()
    encoded = encoder.encode(record)

    # --- Step 4: Determine route ---
    enable_he = (
        mode == "ckks"
        or (mode == "mixed" and bool(sensitivity.get("encryption_required")))
    )

    # --- Step 5: Encrypt sensitive fields ---
    t1 = _time.perf_counter()
    encryptor = CKKSEncryptor()
    adaptive = AdaptiveModule(encryptor=encryptor)
    numeric_record = {k: float(v) for k, v in encoded.items() if k != "anomaly"}
    payload = adaptive.protect(x=numeric_record, flag=enable_he, sensitive_idx=sensitive_fields)
    t_encrypt = _time.perf_counter() - t1

    plain_keys = sorted(payload.get("plain", {}).keys())
    encrypted_keys = sorted(payload.get("encrypted", {}).keys())

    # --- Step 6: Inference ---
    t2 = _time.perf_counter()
    server_url = str(body.get("serverUrl", "")).strip() or INFERENCE_SERVER_URL
    if server_url:
        from server_module.remote_server import RemoteLRModelServer

        server = RemoteLRModelServer(base_url=server_url, ckks_context=encryptor.context)
        inference_location = server_url
    else:
        from server_module.server import LRModelServer

        server = LRModelServer(model_path=MODEL_PATH)
        inference_location = "local"

    z = server.infer(payload)
    t_infer = _time.perf_counter() - t2

    # --- Step 7: Client-side decrypt + decision ---
    t3 = _time.perf_counter()
    decision = ClientDecision(encryptor=encryptor, threshold=0.5)
    result = decision.decide(z, payload, enable_he)
    t_decide = _time.perf_counter() - t3

    total_ms = (t_classify + t_encrypt + (_time.perf_counter() - t2)) * 1000

    return jsonify({
        "steps": [
            {
                "id": 1,
                "name": "原始資料",
                "description": "Client 端接收到的原始事件記錄",
                "data": {k: (str(v) if not isinstance(v, (int, float)) else v) for k, v in raw_display.items()},
                "duration_ms": 0,
            },
            {
                "id": 2,
                "name": "敏感度分類",
                "description": f"分析結果: {sensitivity['sensitivity_level']} (風險分數: {sensitivity['risk_score']:.2f})",
                "data": {
                    "sensitivity_level": sensitivity["sensitivity_level"],
                    "risk_score": round(sensitivity["risk_score"], 4),
                    "is_sensitive": sensitivity["is_sensitive"],
                    "encryption_required": sensitivity["encryption_required"],
                    "reasons": sensitivity.get("reasons", []),
                },
                "duration_ms": round(t_classify * 1000, 3),
            },
            {
                "id": 3,
                "name": "欄位加密決策",
                "description": (
                    f"識別 {len(sensitive_fields)} 個敏感欄位，實際加密 {len(encrypted_keys)} 個"
                    if enable_he
                    else f"識別 {len(sensitive_fields)} 個敏感欄位，但記錄風險為 {sensitivity['sensitivity_level']}，本次不啟用加密"
                ),
                "data": {
                    "sensitive_fields": sensitive_fields,
                    "all_fields": sorted(numeric_record.keys()),
                    "field_status": {
                        k: (
                            "encrypted" if k in encrypted_keys
                            else "sensitive_not_encrypted" if k in sensitive_fields
                            else "plaintext"
                        )
                        for k in sorted(numeric_record.keys())
                    },
                },
                "duration_ms": 0,
            },
            {
                "id": 4,
                "name": "CKKS 加密" if enable_he else "明文傳輸",
                "description": (
                    f"加密 {len(encrypted_keys)} 個欄位，{len(plain_keys)} 個保持明文"
                    if enable_he
                    else "全部欄位以明文傳輸（低風險資料）"
                ),
                "data": {
                    "enable_he": enable_he,
                    "route": "server_mixed_he" if enable_he else "server_plain",
                    "plain_fields": plain_keys,
                    "encrypted_fields": encrypted_keys,
                    "plain_values": {k: round(payload["plain"][k], 4) for k in plain_keys},
                    "original_values": {
                        k: round(numeric_record[k], 4) for k in encrypted_keys if k in numeric_record
                    },
                    "encrypted_preview": {
                        k: _ckks_preview(payload["encrypted"][k]) for k in encrypted_keys
                    },
                },
                "duration_ms": round(t_encrypt * 1000, 3),
            },
            {
                "id": 5,
                "name": "Server 推論",
                "description": f"透過 {'HTTP → ' + inference_location if server_url else '本地'} 進行同態/明文推論",
                "data": {
                    "inference_location": inference_location,
                    "method": "CKKS homomorphic inference" if enable_he else "plaintext inference",
                    "note": "Server 僅使用公鑰運算，無法解密任何欄位" if enable_he else "明文直接計算 z = bias + Σ(w·x)",
                },
                "duration_ms": round(t_infer * 1000, 3),
            },
            {
                "id": 6,
                "name": "Client 解密 + 決策",
                "description": f"{'解密密文結果 → ' if result.decrypted else ''}sigmoid → 閾值判斷",
                "data": {
                    "decrypted": result.decrypted,
                    "z_plain": round(result.z_plain, 6),
                    "probability": round(result.prob, 6),
                    "threshold": 0.5,
                    "is_anomaly": result.is_anomaly,
                    "verdict": "異常" if result.is_anomaly else "正常",
                },
                "duration_ms": round(t_decide * 1000, 3),
            },
        ],
        "summary": {
            "mode": mode,
            "total_ms": round(total_ms, 2),
            "enable_he": enable_he,
            "sensitivity_level": sensitivity["sensitivity_level"],
            "is_anomaly": result.is_anomaly,
            "probability": round(result.prob, 6),
            "inference_location": inference_location,
        },
    })


@app.get("/api/files/<path:file_path>")
def files(file_path: str) -> Any:
    try:
        safe_file = _safe_output_file(file_path)
        return send_file(str(safe_file))
    except Exception:
        return jsonify({"error": "File not found"}), 404


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
