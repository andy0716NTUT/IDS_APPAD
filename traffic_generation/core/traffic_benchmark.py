from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from adaptive_module.core.mixed_protection import MixedProtectionPipeline
from logistic_regression_model.inference.inference_tools import (
    TARGET_COL,
    load_trained_model,
    predict_probabilities,
    resolve_data_dir,
    resolve_model_path,
)


RAW_TO_INTERNAL_COLS = {
    "User ID": "user_id",
    "Timestamp": "timestamp",
    "Login Status": "login_status",
    "IP Address": "ip_address",
    "Device Type": "device_type",
    "Location": "location",
    "Session Duration": "session_duration",
    "Failed Attempts": "failed_attempts",
    "Behavioral Score": "behavioral_score",
    "Anomaly": "anomaly",
}

def _resolve_default_paths() -> tuple[Path, Path, Path]:
    root = Path(__file__).resolve().parents[2]
    dataset_path = resolve_data_dir() / "test_normalized.csv"
    model_path = resolve_model_path()
    output_dir = root / "traffic_generation" / "output"
    return dataset_path, model_path, output_dir


def _to_workspace_relative(path: Path, workspace_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace_root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def _calc_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
    }

    compact_metrics: dict[str, float] = {"accuracy": round(metrics["accuracy"], 4)}
    for key in ("precision", "recall", "f1"):
        value = round(metrics[key], 4)
        if value != 0.0:
            compact_metrics[key] = value

    return compact_metrics


def _latency_stats(latencies_ms: list[float]) -> dict[str, float]:
    arr = np.asarray(latencies_ms, dtype=np.float64)
    return {
        "avg": round(float(arr.mean()), 4),
        "max": round(float(arr.max()), 4),
        "min": round(float(arr.min()), 4),
    }


def _to_internal_record(row: pd.Series) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for raw_col, internal_col in RAW_TO_INTERNAL_COLS.items():
        if raw_col in row:
            record[internal_col] = row[raw_col]
    return record


def run_traffic_benchmark(
    sample_size: int = 500,
    seed: int = 42,
    threshold: float = 0.5,
    dataset_path: Path | None = None,
    model_path: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    default_dataset, default_model, default_output = _resolve_default_paths()
    workspace_root = Path(__file__).resolve().parents[2]
    dataset_path = dataset_path or default_dataset
    model_path = model_path or default_model
    output_dir = output_dir or default_output

    if sample_size <= 0:
        raise ValueError("sample_size must be > 0")

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path)
    sample_n = min(sample_size, len(df))
    sampled_df = df.sample(n=sample_n, random_state=seed).reset_index(drop=True)

    if TARGET_COL not in sampled_df.columns:
        raise KeyError(f"Target column '{TARGET_COL}' not found in dataset")

    model = load_trained_model(model_path)
    protection_pipeline = MixedProtectionPipeline()

    y_true: list[int] = []
    y_plain: list[int] = []
    y_sensitive: list[int] = []
    plain_latencies_ms: list[float] = []
    sensitive_latencies_ms: list[float] = []
    per_sample_rows: list[dict[str, Any]] = []

    for idx, row in sampled_df.iterrows():
        y = int(row[TARGET_COL])
        y_true.append(y)

        row_df = row.to_frame().T

        start_plain = time.perf_counter()
        plain_prob = float(predict_probabilities(model, row_df)[0])
        plain_latency_ms = (time.perf_counter() - start_plain) * 1000.0

        internal_record = _to_internal_record(row)
        sensitive_fields = protection_pipeline.get_sensitive_fields(internal_record)
        start_sensitive = time.perf_counter()
        protected_payload = protection_pipeline.protect_record(
            record=internal_record,
            enable_he=True,
        )
        sensitive_prob = float(predict_probabilities(model, row_df)[0])
        sensitive_latency_ms = (time.perf_counter() - start_sensitive) * 1000.0

        plain_pred = int(plain_prob >= threshold)
        sensitive_pred = int(sensitive_prob >= threshold)

        y_plain.append(plain_pred)
        y_sensitive.append(sensitive_pred)
        plain_latencies_ms.append(plain_latency_ms)
        sensitive_latencies_ms.append(sensitive_latency_ms)

        per_sample_rows.append(
            {
                "sample_idx": int(idx),
                "true_label": y,
                "plain_prob": plain_prob,
                "plain_pred": plain_pred,
                "plain_latency_ms": round(plain_latency_ms, 4),
                "sensitive_prob": sensitive_prob,
                "sensitive_pred": sensitive_pred,
                "sensitive_latency_ms": round(sensitive_latency_ms, 4),
                "sensitive_field_count": len(sensitive_fields),
                "sensitive_fields": "|".join(sensitive_fields),
                "encrypted_field_count": len(protected_payload["encrypted"]),
            }
        )

    y_true_arr = np.asarray(y_true, dtype=np.int64)
    y_plain_arr = np.asarray(y_plain, dtype=np.int64)
    y_sensitive_arr = np.asarray(y_sensitive, dtype=np.int64)

    plain_metrics = _calc_metrics(y_true_arr, y_plain_arr)
    sensitive_metrics = _calc_metrics(y_true_arr, y_sensitive_arr)

    plain_latency_stats = _latency_stats(plain_latencies_ms)
    sensitive_latency_stats = _latency_stats(sensitive_latencies_ms)

    results = {
        "config": {
            "dataset_path": _to_workspace_relative(dataset_path, workspace_root),
            "model_path": _to_workspace_relative(model_path, workspace_root),
            "output_dir": _to_workspace_relative(output_dir, workspace_root),
            "sample_size_requested": sample_size,
            "sample_size_actual": sample_n,
            "seed": seed,
            "threshold": threshold,
        },
        "plaintext": {
            "metrics": plain_metrics,
            "latency_ms": plain_latency_stats,
        },
        "sensitive_protected": {
            "metrics": sensitive_metrics,
            "latency_ms": sensitive_latency_stats,
        },
        "comparison": {
            "accuracy_delta": round(sensitive_metrics["accuracy"] - plain_metrics["accuracy"], 4),
            "avg_latency_delta_ms": round(sensitive_latency_stats["avg"] - plain_latency_stats["avg"], 4),
        },
    }

    pd.DataFrame(per_sample_rows).to_csv(output_dir / "traffic_benchmark_predictions.csv", index=False)
    with (output_dir / "traffic_benchmark_metrics.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    return results

if __name__ == "__main__":

    results = run_traffic_benchmark(
        sample_size=10,
        seed=42,
        threshold=0.5,
    )

    import json
    print(json.dumps(results, indent=2))