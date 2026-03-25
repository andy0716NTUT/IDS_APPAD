from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from logistic_regression_model.core.logistic_regression_plain import LogisticRegressionPlain
from logistic_regression_model.inference.logistic_regression_ckks import LogisticRegressionCKKS


CSV_TO_INTERNAL = {
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

DEFAULT_THRESHOLD = 0.5
DEFAULT_PRIVACY_RATIOS = [10, 20, 30, 40, 50, 60, 70, 80, 90]


def resolve_default_dataset() -> Path:
    return Path(__file__).resolve().parents[2] / "dataset" / "synthetic_web_auth_logs.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot APPAD metrics vs privacy-sensitive data ratio. "
            "Outputs 4 figures: Accuracy, Latency, Information Leakage, Detection Efficiency."
        )
    )
    parser.add_argument("--dataset-path", type=str, default=str(resolve_default_dataset()))
    parser.add_argument("--sample-size", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--inference-mode",
        type=str,
        choices=["plaintext", "ckks"],
        default="ckks",
        help="Use plaintext or CKKS inference while sweeping privacy ratio.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(Path(__file__).resolve().parents[2] / "output_results" / "privacy_ratio_plots"),
    )
    parser.add_argument(
        "--privacy-ratios",
        type=int,
        nargs="+",
        default=DEFAULT_PRIVACY_RATIOS,
        help="Privacy-sensitive data ratio percentages, e.g. 10 20 30 ... 90",
    )
    parser.add_argument(
        "--allow-plaintext-fallback",
        action="store_true",
        help="If CKKS initialization fails, fallback to plaintext instead of stopping.",
    )
    return parser.parse_args()


def to_internal_record(row: pd.Series) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for csv_col, internal_col in CSV_TO_INTERNAL.items():
        if csv_col in row:
            record[internal_col] = row[csv_col]
    return record


def select_sensitive_fields(record: dict[str, Any], ratio_percent: int) -> set[str]:
    non_label_fields = sorted([k for k in record.keys() if k != "anomaly"])
    if not non_label_fields:
        return set()
    ratio = max(0.0, min(1.0, ratio_percent / 100.0))
    count = int(round(ratio * len(non_label_fields)))
    count = max(0, min(count, len(non_label_fields)))
    return set(non_label_fields[:count])


def compute_metrics_for_ratio(
    sampled_df: pd.DataFrame,
    ratio_percent: int,
    inference_mode: str,
    plain_model: LogisticRegressionPlain,
    ckks_model: LogisticRegressionCKKS | None,
) -> dict[str, float]:
    y_true: list[int] = []
    y_pred: list[int] = []
    latencies_ms: list[float] = []
    p_per_flow: list[float] = []
    flow_size_bytes: list[int] = []

    for _, row in sampled_df.iterrows():
        record = to_internal_record(row)
        non_label_fields = [k for k in record.keys() if k != "anomaly"]
        sensitive_fields = select_sensitive_fields(record, ratio_percent)

        start = time.perf_counter()
        if inference_mode == "ckks":
            if ckks_model is None:
                raise RuntimeError("CKKS model is not initialized")
            prob, _, _ = ckks_model.predict_proba(record=record, sensitive_fields=sensitive_fields)
        else:
            prob = float(plain_model.predict_proba(record))
        latency_ms = (time.perf_counter() - start) * 1000.0

        label = int(row["Anomaly"])
        pred = int(prob >= DEFAULT_THRESHOLD)

        y_true.append(label)
        y_pred.append(pred)
        latencies_ms.append(latency_ms)

        p_i = len(sensitive_fields) / max(len(non_label_fields), 1)
        l_i = sum(len(str(record[k]).encode("utf-8")) for k in non_label_fields)
        p_per_flow.append(p_i)
        flow_size_bytes.append(l_i)

    y_true_arr = np.asarray(y_true, dtype=np.int64)
    y_pred_arr = np.asarray(y_pred, dtype=np.int64)
    latency_arr = np.asarray(latencies_ms, dtype=np.float64)

    accuracy = float(accuracy_score(y_true_arr, y_pred_arr)) if len(y_true_arr) else 0.0

    n_flows = int(len(sampled_df))
    p_sensitive = float(np.mean(np.asarray(p_per_flow, dtype=np.float64))) if p_per_flow else 0.0
    l_flow_size = float(np.mean(np.asarray(flow_size_bytes, dtype=np.float64))) if flow_size_bytes else 0.0
    d_latency = float(latency_arr.mean()) if len(latency_arr) else 0.0
    lt_information_leakage = float(n_flows * p_sensitive * l_flow_size)

    if d_latency > 0.0 and lt_information_leakage > 0.0:
        detection_efficiency = float(accuracy / (d_latency * lt_information_leakage))
    else:
        detection_efficiency = 0.0

    return {
        "privacy_sensitive_data_ratio": float(ratio_percent),
        "accuracy": accuracy,
        "latency_ms": d_latency,
        "information_leakage": lt_information_leakage,
        "detection_efficiency": detection_efficiency,
    }


def style_axis(ax: plt.Axes, ylabel: str, x_values: list[int]) -> None:
    ax.set_facecolor("#E7E7E7")
    ax.grid(True, color="#BDBDBD", linewidth=1.0)
    ax.set_xlabel("Privacy-sensitive data ratio (%)", fontsize=14, fontweight="bold")
    ax.set_ylabel(ylabel, fontsize=14, fontweight="bold")
    ax.set_xticks(x_values)
    for spine in ax.spines.values():
        spine.set_linewidth(1.2)


def plot_metric(
    x_values: list[int],
    y_values: list[float],
    ylabel: str,
    output_path: Path,
    y_limits: tuple[float, float] | None = None,
) -> None:
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=120)

    ax.plot(
        x_values,
        y_values,
        linestyle=(0, (5, 4)),
        color="#1F1F1F",
        marker="^",
        markersize=6,
        markerfacecolor="none",
        markeredgecolor="#1F1F1F",
        markeredgewidth=1.2,
        linewidth=1.3,
        label="APPAD",
    )

    style_axis(ax, ylabel=ylabel, x_values=x_values)
    if y_limits is not None:
        ax.set_ylim(*y_limits)
    ax.legend(
        loc="best",
        frameon=True,
        facecolor="#E7E7E7",
        edgecolor="black",
        framealpha=1.0,
        fancybox=False,
    )
    fig.tight_layout()
    fig.savefig(output_path, dpi=300)
    plt.close(fig)


def main() -> None:
    args = parse_args()

    if args.sample_size <= 0:
        raise ValueError("sample-size must be > 0")

    dataset_path = Path(args.dataset_path)
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    privacy_ratios = sorted(set(args.privacy_ratios))
    for ratio in privacy_ratios:
        if ratio < 0 or ratio > 100:
            raise ValueError("privacy-ratios must be in [0, 100]")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path)
    if "Anomaly" not in df.columns:
        raise KeyError("Dataset must include 'Anomaly' column")

    sample_n = min(args.sample_size, len(df))
    sampled_df = df.sample(n=sample_n, random_state=args.seed).reset_index(drop=True)

    plain_model = LogisticRegressionPlain()
    inference_mode = args.inference_mode
    ckks_model: LogisticRegressionCKKS | None = None

    if inference_mode == "ckks":
        try:
            ckks_model = LogisticRegressionCKKS()
        except Exception as exc:
            if args.allow_plaintext_fallback:
                inference_mode = "plaintext"
                print(f"[WARN] CKKS unavailable, fallback to plaintext: {exc}")
            else:
                raise

    rows: list[dict[str, float]] = []
    for ratio in privacy_ratios:
        metrics = compute_metrics_for_ratio(
            sampled_df=sampled_df,
            ratio_percent=ratio,
            inference_mode=inference_mode,
            plain_model=plain_model,
            ckks_model=ckks_model,
        )
        rows.append(metrics)

    result_df = pd.DataFrame(rows).sort_values("privacy_sensitive_data_ratio").reset_index(drop=True)

    csv_path = output_dir / "appad_metrics_vs_privacy_ratio.csv"
    result_df.to_csv(csv_path, index=False)

    x_values = result_df["privacy_sensitive_data_ratio"].astype(int).tolist()

    accuracy_vals = result_df["accuracy"].tolist()
    latency_vals = result_df["latency_ms"].tolist()
    leakage_vals = result_df["information_leakage"].tolist()
    efficiency_vals = result_df["detection_efficiency"].tolist()

    plot_metric(
        x_values=x_values,
        y_values=accuracy_vals,
        ylabel="Accuracy",
        output_path=output_dir / "appad_accuracy_vs_privacy_ratio.png",
        y_limits=(0.0, 1.0),
    )
    plot_metric(
        x_values=x_values,
        y_values=latency_vals,
        ylabel="Latency (ms)",
        output_path=output_dir / "appad_latency_vs_privacy_ratio.png",
    )
    plot_metric(
        x_values=x_values,
        y_values=leakage_vals,
        ylabel="Information Leakage",
        output_path=output_dir / "appad_information_leakage_vs_privacy_ratio.png",
    )
    plot_metric(
        x_values=x_values,
        y_values=efficiency_vals,
        ylabel="Detection Efficiency",
        output_path=output_dir / "appad_detection_efficiency_vs_privacy_ratio.png",
    )

    summary = {
        "dataset_path": str(dataset_path),
        "sample_size": int(sample_n),
        "seed": int(args.seed),
        "inference_mode_requested": args.inference_mode,
        "inference_mode_used": inference_mode,
        "privacy_ratios": x_values,
        "csv": str(csv_path),
    }
    summary_path = output_dir / "appad_privacy_ratio_plot_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("APPAD privacy-ratio plotting complete.")
    print(f"CSV: {csv_path}")
    print(f"Summary: {summary_path}")
    print(f"Figure: {output_dir / 'appad_accuracy_vs_privacy_ratio.png'}")
    print(f"Figure: {output_dir / 'appad_latency_vs_privacy_ratio.png'}")
    print(f"Figure: {output_dir / 'appad_information_leakage_vs_privacy_ratio.png'}")
    print(f"Figure: {output_dir / 'appad_detection_efficiency_vs_privacy_ratio.png'}")


if __name__ == "__main__":
    main()
