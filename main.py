from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from classifier.core.classifier import SensitivityClassifier
from classifier.core.feature_sensitivity import FeatureSensitivityClassifier
from logistic_regression_model.inference.logistic_regression_ckks import LogisticRegressionCKKS
from logistic_regression_model.core.logistic_regression_plain import LogisticRegressionPlain


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


def resolve_default_dataset() -> Path:
    return Path(__file__).resolve().parent / "dataset" / "synthetic_web_auth_logs.csv"


def to_internal_record(row: pd.Series) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for csv_col, internal_col in CSV_TO_INTERNAL.items():
        if csv_col in row:
            out[internal_col] = row[csv_col]
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "APPAD main pipeline: traffic generation -> sensitivity classification "
            "-> plaintext/CKKS inference -> metrics"
        )
    )
    parser.add_argument("--dataset-path", type=str, default=str(resolve_default_dataset()))
    parser.add_argument("--sample-size", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--inference-mode",
        type=str,
        choices=["plaintext", "ckks"],
        default="plaintext",
        help="Choose inference path: plaintext or CKKS privacy inference",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(Path(__file__).resolve().parent / "output_results"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.sample_size <= 0:
        raise ValueError("sample_size must be > 0")

    dataset_path = Path(args.dataset_path)
    output_dir = Path(args.output_dir)

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if "Anomaly" not in df.columns:
        raise KeyError("Dataset must include 'Anomaly' column for metric calculation")

    sample_n = min(args.sample_size, len(df))
    sampled_df = df.sample(n=sample_n, random_state=args.seed).reset_index(drop=True)

    classifier = SensitivityClassifier()
    feature_sensitivity_classifier = FeatureSensitivityClassifier()
    plain_model = LogisticRegressionPlain()

    ckks_model: LogisticRegressionCKKS | None = None
    if args.inference_mode == "ckks":
        ckks_model = LogisticRegressionCKKS()

    y_true: list[int] = []
    y_pred: list[int] = []
    latencies_ms: list[float] = []
    sensitive_ratio_per_flow: list[float] = []
    flow_size_bytes: list[int] = []
    rows: list[dict[str, Any]] = []

    for idx, row in sampled_df.iterrows():
        record = to_internal_record(row)
        start = time.perf_counter()

        sensitivity = classifier.classify(record)
        sensitive_fields = set(feature_sensitivity_classifier.sensitive_indices(record))

        # Formula terms for information leakage (Lt = N * p * l)
        non_label_fields = [k for k in record.keys() if k != "anomaly"]
        sensitive_non_label_fields = [k for k in sensitive_fields if k != "anomaly"]
        p_i = len(sensitive_non_label_fields) / max(len(non_label_fields), 1)
        l_i = sum(len(str(record[k]).encode("utf-8")) for k in non_label_fields)

        if args.inference_mode == "ckks":
            if ckks_model is None:
                raise RuntimeError("CKKS model is not initialized")
            prob, _, encrypted_feature_list = ckks_model.predict_proba(
                record=record,
                sensitive_fields=sensitive_fields,
            )
            detection_path = "ckks_privacy_inference"
        else:
            prob = float(plain_model.predict_proba(record))
            encrypted_feature_list = []
            detection_path = "plaintext_inference"

        pred = int(prob >= DEFAULT_THRESHOLD)

        latency_ms = (time.perf_counter() - start) * 1000.0

        label = int(row["Anomaly"])
        y_true.append(label)
        y_pred.append(pred)
        latencies_ms.append(latency_ms)
        sensitive_ratio_per_flow.append(p_i)
        flow_size_bytes.append(l_i)

        rows.append(
            {
                "sample_idx": int(idx),
                "true_label": label,
                "pred_label": pred,
                "anomaly_prob": round(prob, 4),
                "threshold": DEFAULT_THRESHOLD,
                "sensitivity_level": sensitivity["sensitivity_level"],
                "risk_score": sensitivity["risk_score"],
                "is_sensitive": bool(sensitivity["is_sensitive"]),
                "encryption_required": bool(sensitivity["encryption_required"]),
                "detection_path": detection_path,
                "sensitive_fields": "|".join(sorted(sensitive_fields)),
                "encrypted_fields": "|".join(encrypted_feature_list),
                "encrypted_field_count": len(encrypted_feature_list),
                "latency_ms": round(latency_ms, 4),
                "reasons": "|".join(sensitivity["reasons"]),
            }
        )

    y_true_arr = np.asarray(y_true, dtype=np.int64)
    y_pred_arr = np.asarray(y_pred, dtype=np.int64)
    latency_arr = np.asarray(latencies_ms, dtype=np.float64)

    accuracy = float(accuracy_score(y_true_arr, y_pred_arr))
    precision = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    recall = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))

    # Detection Efficiency formula from spec:
    #   Lt = N * p * l
    #   Meff = Acc / (d * Lt)
    n_flows = int(sample_n)
    p_sensitive = float(np.mean(np.asarray(sensitive_ratio_per_flow, dtype=np.float64))) if sensitive_ratio_per_flow else 0.0
    l_flow_size = float(np.mean(np.asarray(flow_size_bytes, dtype=np.float64))) if flow_size_bytes else 0.0
    d_latency = float(latency_arr.mean()) if len(latency_arr) else 0.0
    lt_information_leakage = float(n_flows * p_sensitive * l_flow_size)

    if d_latency > 0.0 and lt_information_leakage > 0.0:
        detection_efficiency = float(accuracy / (d_latency * lt_information_leakage))
    else:
        detection_efficiency = 0.0

    results = {
        "config": {
            "dataset_path": str(dataset_path),
            "sample_size_requested": int(args.sample_size),
            "sample_size_actual": int(sample_n),
            "seed": int(args.seed),
            "threshold": DEFAULT_THRESHOLD,
            "inference_mode": args.inference_mode,
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "detection_efficiency": round(detection_efficiency, 8),
            "information_leakage": round(lt_information_leakage, 6),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "formula_terms": {
            "N": n_flows,
            "p": round(p_sensitive, 6),
            "l": round(l_flow_size, 4),
            "d": round(d_latency, 6),
            "Lt": round(lt_information_leakage, 6),
            "definition": "detection_efficiency = accuracy / (d * Lt), Lt = N * p * l",
        },
        "latency_ms": {
            "avg": round(float(latency_arr.mean()), 4),
            "max": round(float(latency_arr.max()), 4),
            "min": round(float(latency_arr.min()), 4),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    pred_path = output_dir / f"appad_main_predictions_{args.inference_mode}.csv"
    metrics_path = output_dir / f"appad_main_metrics_{args.inference_mode}.json"

    pd.DataFrame(rows).to_csv(pred_path, index=False)
    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("APPAD main pipeline complete.")
    print(f"Predictions saved to: {pred_path}")
    print(f"Metrics saved to: {metrics_path}")
    print(
        "Accuracy={:.4f}, Information Leakage(Lt)={:.4f}, Detection Efficiency={:.4f}, Avg Latency(ms)={:.4f}".format(
            results["metrics"]["accuracy"],
            results["metrics"]["information_leakage"],
            results["metrics"]["detection_efficiency"],
            results["latency_ms"]["avg"],
        )
    )


if __name__ == "__main__":
    main()