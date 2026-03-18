"""
End-to-end pipeline demo: traffic → classify → route → protect → infer → decide.

Usage:
    python -m pipeline.run_pipeline_demo --sample-size 20
    python -m pipeline.run_pipeline_demo --sample-size 50 --threshold 0.6
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pipeline.end_to_end import EndToEndPipeline, PipelineConfig


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="IDS APPAD End-to-End Pipeline Demo")
    parser.add_argument("--sample-size", type=int, default=20)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=str, default=None)
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir) if args.output_dir else None

    config = PipelineConfig(
        sample_size=args.sample_size,
        decision_threshold=args.threshold,
        seed=args.seed,
        output_dir=output_dir,
    )

    print(f"=== IDS APPAD End-to-End Pipeline ===")
    print(f"Sample size: {args.sample_size}  |  Threshold: {args.threshold}  |  Seed: {args.seed}")
    print()

    pipeline = EndToEndPipeline(config)

    print(f"Server weights (from trained model):")
    for k, v in pipeline.server.weights.items():
        print(f"  {k}: {v:.6f}")
    print(f"  bias: {pipeline.server.bias:.6f}")
    print()

    print("Running pipeline...")
    results = pipeline.run()
    print()

    print("=== Metrics ===")
    for k, v in results["metrics"].items():
        print(f"  {k}: {v}")

    print()
    print("=== Latency ===")
    for k, v in results["latency"].items():
        print(f"  {k}: {v}")

    print()
    print("=== Route Distribution ===")
    for route, pct in results["route_distribution"].items():
        count = results["route_counts"][route]
        print(f"  {route}: {count} ({pct}%)")

    print()
    print(f"Output saved to: {pipeline.output_dir}")


if __name__ == "__main__":
    main()
