from __future__ import annotations

import argparse
import sys
from pathlib import Path


if __package__ is None or __package__ == "":
    workspace_root = Path(__file__).resolve().parents[2]
    if str(workspace_root) not in sys.path:
        sys.path.insert(0, str(workspace_root))

from traffic_generation.core.traffic_benchmark import run_traffic_benchmark
from logistic_regression_model.inference.run_logistic_regression_inference import resolve_data_dir


def main() -> None:
    root = Path(__file__).resolve().parents[2]

    parser = argparse.ArgumentParser(
        description="Generate random traffic samples and benchmark plaintext vs sensitive-protected inference"
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default=str(resolve_data_dir() / "test_normalized.csv"),
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=str(root / "logistic_regression_model" / "output_lr" / "lr_model.joblib"),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(root / "traffic_generation" / "output"),
    )
    parser.add_argument("--sample-size", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold", type=float, default=0.5)

    args = parser.parse_args()

    results = run_traffic_benchmark(
        sample_size=args.sample_size,
        seed=args.seed,
        threshold=args.threshold,
        dataset_path=Path(args.dataset_path),
        model_path=Path(args.model_path),
        output_dir=Path(args.output_dir),
    )

    print("Traffic benchmark complete.")
    plain_metrics = results["plaintext"]["metrics"]
    sensitive_metrics = results["sensitive_protected"]["metrics"]
    plain_latency = results["plaintext"]["latency_ms"]
    sensitive_latency = results["sensitive_protected"]["latency_ms"]

    print("=== 流量推論評估結果 ===")
    print(f"樣本數: {results['config']['sample_size_actual']}")
    print(f"明文準確率: {plain_metrics['accuracy']}")
    print(f"敏感保護準確率: {sensitive_metrics['accuracy']}")
    print(
        f"明文延遲 - 平均: {plain_latency['avg']} ms, 最慢: {plain_latency['max']} ms, 最快: {plain_latency['min']} ms"
    )
    print(
        f"敏感保護延遲 - 平均: {sensitive_latency['avg']} ms, 最慢: {sensitive_latency['max']} ms, 最快: {sensitive_latency['min']} ms"
    )


if __name__ == "__main__":
    main()
