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


app = Flask(__name__)


@app.get("/api/health")
def health() -> Any:
    return jsonify({"ok": True})


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


@app.get("/api/files/<path:file_path>")
def files(file_path: str) -> Any:
    try:
        safe_file = _safe_output_file(file_path)
        return send_file(str(safe_file))
    except Exception:
        return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
