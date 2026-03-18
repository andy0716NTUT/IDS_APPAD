from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from adaptive_routing.adaptive_router import RoutingConfig
from adaptive_routing.system import IDSSystem, IDSSystemConfig
from ckks_homomorphic_encryption.he_encryptor import PaillierEncryptor
from logistic_regression_model.inference.inference_tools import (
    TARGET_COL,
    resolve_data_dir,
)
from server_module.server import TrainedModelServer
from traffic_generation.core.traffic_benchmark import RAW_TO_INTERNAL_COLS


def _resolve_defaults() -> tuple[Path, Path, Path]:
    root = Path(__file__).resolve().parents[1]
    dataset_path = resolve_data_dir() / "test_normalized.csv"
    model_path = root / "logistic_regression_model" / "output_lr" / "lr_model.joblib"
    output_dir = root / "pipeline" / "output"
    return dataset_path, model_path, output_dir


def _to_internal_record(row: pd.Series) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for raw_col, internal_col in RAW_TO_INTERNAL_COLS.items():
        if raw_col in row:
            record[internal_col] = row[raw_col]
    return record


def _calc_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }


def _latency_stats(values: list[float]) -> dict[str, float]:
    arr = np.asarray(values, dtype=np.float64)
    return {
        "avg_ms": round(float(arr.mean()), 2),
        "min_ms": round(float(arr.min()), 2),
        "max_ms": round(float(arr.max()), 2),
    }


@dataclass
class PipelineConfig:
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    decision_threshold: float = 0.5
    dataset_path: Path | None = None
    model_path: Path | None = None
    output_dir: Path | None = None
    sample_size: int = 100
    seed: int = 42


class EndToEndPipeline:
    """
    Unified end-to-end pipeline:
    traffic load → classify → route → protect → server infer → client decide.

    Uses TrainedModelServer (real trained LR weights) instead of hardcoded stub.
    """

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()

        default_dataset, default_model, default_output = _resolve_defaults()
        self.dataset_path = self.config.dataset_path or default_dataset
        self.model_path = self.config.model_path or default_model
        self.output_dir = self.config.output_dir or default_output

        # Build system components
        self.encryptor = PaillierEncryptor()
        self.server = TrainedModelServer(model_path=self.model_path)
        self.system = IDSSystem(
            config=IDSSystemConfig(
                routing=self.config.routing,
                decision_threshold=self.config.decision_threshold,
            ),
            encryptor=self.encryptor,
            server=self.server,
        )

    def run(self) -> dict[str, Any]:
        """Execute the full pipeline and return results with metrics."""
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)
        sample_n = min(self.config.sample_size, len(df))
        sampled = df.sample(n=sample_n, random_state=self.config.seed).reset_index(drop=True)

        if TARGET_COL not in sampled.columns:
            raise KeyError(f"Target column '{TARGET_COL}' not found in dataset")

        y_true: list[int] = []
        y_pred: list[int] = []
        latencies: list[float] = []
        route_counts: dict[str, int] = {}
        per_record: list[dict[str, Any]] = []

        for idx, row in sampled.iterrows():
            label = int(row[TARGET_COL])
            record = _to_internal_record(row)

            result = self.system.process_event(record)

            y_true.append(label)
            y_pred.append(int(result["is_anomaly"]))
            latencies.append(result["latency_ms"])

            route = result["route"]
            route_counts[route] = route_counts.get(route, 0) + 1

            per_record.append({
                "idx": int(idx),
                "true_label": label,
                "route": route,
                "enable_he": result["enable_he"],
                "sensitivity": result["sensitivity"],
                "prob": round(result["prob"], 6),
                "is_anomaly": result["is_anomaly"],
                "decrypted": result["decrypted"],
                "latency_ms": round(result["latency_ms"], 2),
            })

        y_true_arr = np.asarray(y_true, dtype=np.int64)
        y_pred_arr = np.asarray(y_pred, dtype=np.int64)

        metrics = _calc_metrics(y_true_arr, y_pred_arr)
        latency = _latency_stats(latencies)

        # Route distribution as percentages
        route_dist = {
            k: round(v / sample_n * 100, 1)
            for k, v in sorted(route_counts.items())
        }

        summary = {
            "config": {
                "dataset": str(self.dataset_path),
                "model": str(self.model_path),
                "sample_size": sample_n,
                "seed": self.config.seed,
                "threshold": self.config.decision_threshold,
            },
            "server_weights": self.server.weights,
            "server_bias": self.server.bias,
            "metrics": metrics,
            "latency": latency,
            "route_distribution": route_dist,
            "route_counts": dict(sorted(route_counts.items())),
        }

        # Write outputs
        self.output_dir.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(per_record).to_csv(
            self.output_dir / "pipeline_predictions.csv", index=False
        )
        with (self.output_dir / "pipeline_results.json").open("w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        return summary
