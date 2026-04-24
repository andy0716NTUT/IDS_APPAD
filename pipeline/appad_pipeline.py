from __future__ import annotations

import argparse
import re
import json
import time
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from classifier.core.classifier import SensitivityClassifier
from classifier.core.feature_sensitivity import FeatureSensitivityClassifier
from logistic_regression_model.inference.inference_tools import resolve_data_dir, resolve_model_path
from server_module.server import LRModelServer

# Lazy imports for remote mode (avoid hard dependency on requests)
# from adaptive_module.core.adaptive_module import AdaptiveModule
# from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
# from decision_module.client_decision import ClientDecision
# from server_module.remote_server import RemoteLRModelServer


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

MODEL_FEATURE_COLS = ["User ID", "Session Duration", "Failed Attempts", "Behavioral Score"]

DEFAULT_THRESHOLD = 0.5
DEFAULT_PRIVACY_RATIOS = [10, 20, 30, 40, 50, 60, 70, 80, 90]
EFFICIENCY_EPSILON = 1e-12
FIXED_P_SENSITIVE = 0.5
BITS_PER_KB = 1000.0
PRE_SENSITIVE_FLAG_COLS = [
    "sensitive_needs_encryption",
    "pre_is_sensitive",
    "is_sensitive_pre",
]
LABEL_LIKE_COLS = {"anomaly", "label", "target", "y", "class"}
DEFAULT_PRE_SENSITIVE_SIDECAR = Path(__file__).resolve().parents[1] / "dataset" / "synthetic_web_auth_logs_sensitive_flag.csv"


def resolve_default_dataset() -> Path:
    # Keep inference data distribution consistent with training (normalized features).
    return resolve_data_dir() / "test_normalized.csv"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "APPAD pipeline: traffic generation -> sensitivity classification "
            "-> plaintext/CKKS inference -> metrics"
        )
    )
    parser.add_argument("--dataset-path", type=str, default=str(resolve_default_dataset()))
    parser.add_argument("--model-path", type=str, default=str(resolve_model_path()))
    parser.add_argument("--sample-size", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--inference-mode",
        type=str,
        choices=["plaintext", "ckks", "mixed"],
        default="mixed",
        help="Choose inference path: plaintext, ckks, or mixed (recommended default).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=str(Path(__file__).resolve().parents[1] / "output_results"),
    )
    parser.add_argument(
        "--skip-privacy-ratio-sweep",
        action="store_true",
        help="Skip privacy-sensitive data ratio sweep (default behavior is to run and regenerate plots).",
    )
    parser.add_argument(
        "--privacy-ratios",
        type=str,
        default=",".join(str(v) for v in DEFAULT_PRIVACY_RATIOS),
        help="Comma-separated privacy-sensitive data ratios. Example: 10,20,30,...,90",
    )
    parser.add_argument(
        "--allow-plaintext-fallback",
        action="store_true",
        help="When ckks mode is requested but unavailable, fallback to plaintext.",
    )
    parser.add_argument(
        "--auto-train-if-missing",
        action="store_true",
        help="Automatically run LR training script if model file is missing.",
    )
    parser.add_argument(
        "--allow-unscaled-dataset",
        action="store_true",
        help=(
            "Bypass normalized feature consistency check. "
            "Use only when your model is trained on the same unscaled/raw feature distribution."
        ),
    )
    parser.add_argument(
        "--server-url",
        type=str,
        default=None,
        help="Remote inference server URL (e.g. http://127.0.0.1:5001). "
             "When set, inference is forwarded over HTTP instead of running locally.",
    )
    return parser


def parse_ratio_list(ratio_text: str) -> list[int]:
    ratios = [int(part.strip()) for part in ratio_text.split(",") if part.strip()]
    if not ratios:
        raise ValueError("privacy-ratios cannot be empty")
    dedup = sorted(set(ratios))
    for value in dedup:
        if value < 0 or value > 100:
            raise ValueError("privacy-ratios must be in [0, 100]")
    return dedup


def to_internal_record(row: pd.Series) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for csv_col, internal_col in CSV_TO_INTERNAL.items():
        if csv_col in row:
            out[internal_col] = row[csv_col]
    return out


def select_sensitive_traffic_indices(total_count: int, ratio_percent: int, seed: int) -> set[int]:
    if total_count <= 0:
        return set()

    ratio = max(0.0, min(1.0, ratio_percent / 100.0))
    sensitive_count = int(round(total_count * ratio))
    sensitive_count = max(0, min(sensitive_count, total_count))

    rng = np.random.default_rng(seed)
    selected = rng.choice(total_count, size=sensitive_count, replace=False)
    return set(int(v) for v in selected)


def calc_flow_size_bits(record: dict[str, Any]) -> int:
    non_label_fields = [k for k in record.keys() if k != "anomaly"]
    total_bytes = sum(len(str(record[k]).encode("utf-8")) for k in non_label_fields)
    return int(total_bytes * 8)


def _to_pre_sensitive_label(value: Any) -> str:
    if isinstance(value, (bool, np.bool_)):
        return "敏感" if bool(value) else "非敏感"
    if isinstance(value, (int, np.integer, float, np.floating)):
        return "敏感" if float(value) != 0.0 else "非敏感"
    text = str(value).strip().lower()
    if text in {"1", "true", "t", "yes", "y", "sensitive", "high", "medium"}:
        return "敏感"
    if text in {"0", "false", "f", "no", "n", "nonsensitive", "non-sensitive", "low"}:
        return "非敏感"
    return "未知"


def get_pre_sensitive_label(row: pd.Series) -> str:
    for col in PRE_SENSITIVE_FLAG_COLS:
        if col in row.index:
            return _to_pre_sensitive_label(row[col])

    # Fallback: some datasets keep pre-sensitive flag in the last column.
    if len(row.index) > 0:
        last_col = str(row.index[-1])
        last_col_lower = last_col.strip().lower()
        if (
            "sensitive" in last_col_lower
            or "privacy" in last_col_lower
            or "encrypt" in last_col_lower
            or last_col_lower not in LABEL_LIKE_COLS
        ):
            candidate = _to_pre_sensitive_label(row[last_col])
            if candidate != "未知":
                return candidate
    return "未知"


def check_feature_scale_consistency(df: pd.DataFrame, feature_cols: list[str]) -> tuple[bool, dict[str, dict[str, float]]]:
    """Check whether inference features look normalized to [0, 1]."""
    details: dict[str, dict[str, float]] = {}
    inconsistent = False

    for col in feature_cols:
        if col not in df.columns:
            inconsistent = True
            details[col] = {
                "missing": 1.0,
                "min": float("nan"),
                "max": float("nan"),
                "outside_ratio": 1.0,
            }
            continue

        numeric = pd.to_numeric(df[col], errors="coerce")
        valid = numeric.dropna()
        if valid.empty:
            inconsistent = True
            details[col] = {
                "missing": 0.0,
                "min": float("nan"),
                "max": float("nan"),
                "outside_ratio": 1.0,
            }
            continue

        min_v = float(valid.min())
        max_v = float(valid.max())
        outside = ((valid < -1e-6) | (valid > 1.000001)).sum()
        outside_ratio = float(outside) / float(len(valid))

        details[col] = {
            "missing": 0.0,
            "min": min_v,
            "max": max_v,
            "outside_ratio": outside_ratio,
        }

        if min_v < -1e-3 or max_v > 1.001 or outside_ratio > 0.01:
            inconsistent = True

    return (not inconsistent), details


def infer_sidecar_label_column(sidecar_df: pd.DataFrame) -> str | None:
    for col in PRE_SENSITIVE_FLAG_COLS:
        if col in sidecar_df.columns:
            return col
    if len(sidecar_df.columns) == 0:
        return None
    return str(sidecar_df.columns[-1])


def calc_traffic_breakdown_bytes(
    record: dict[str, Any],
    sensitive_fields: set[str],
    encrypted_fields: list[str],
) -> dict[str, int]:
    non_label_fields = {k for k in record.keys() if k != "anomaly"}
    sensitive_non_label_fields = {k for k in sensitive_fields if k in non_label_fields}
    encrypted_non_label_fields = {k for k in encrypted_fields if k in non_label_fields}

    ciphertext_sensitive_fields = encrypted_non_label_fields & sensitive_non_label_fields
    ciphertext_nonsensitive_fields = encrypted_non_label_fields - sensitive_non_label_fields
    plaintext_nonsensitive_fields = (non_label_fields - sensitive_non_label_fields) - ciphertext_nonsensitive_fields

    return {
        "plaintext_nonsensitive": int(sum(len(str(record[k]).encode("utf-8")) for k in plaintext_nonsensitive_fields)),
        "ciphertext_sensitive": int(sum(len(str(record[k]).encode("utf-8")) for k in ciphertext_sensitive_fields)),
    }


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def persist_raw_ciphertext(value: Any, file_path: Path) -> int:
    """Persist raw CKKS serialized bytes without extra encoding transform."""
    serialize = getattr(value, "serialize", None)
    if not callable(serialize):
        raise TypeError("Ciphertext object does not support serialize()")

    raw = serialize()
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("Serialized ciphertext is not bytes")

    payload = bytes(raw)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(payload)
    return int(len(payload))


def _plot_metric(
    x_values: list[int],
    y_values: list[float],
    y_label: str,
    output_path: Path,
    y_limits: tuple[float, float] | None = None,
) -> None:
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=120)
    ax.set_facecolor("#E7E7E7")

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

    ax.grid(True, color="#BDBDBD", linewidth=1.0)
    ax.set_xlabel("Privacy-sensitive data ratio (%)", fontsize=14, fontweight="bold")
    ax.set_ylabel(y_label, fontsize=14, fontweight="bold")
    ax.set_xticks(x_values)
    if y_limits is not None:
        ax.set_ylim(*y_limits)

    for spine in ax.spines.values():
        spine.set_linewidth(1.2)

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


def run_privacy_ratio_sweep(
    sampled_df: pd.DataFrame,
    privacy_ratios: list[int],
    seed: int,
    inference_mode: str,
    server: Any,
    feature_sensitivity_classifier: FeatureSensitivityClassifier,
    output_dir: Path,
    *,
    remote_helpers: dict[str, Any] | None = None,
) -> None:
    rows: list[dict[str, float]] = []

    for ratio_percent in privacy_ratios:
        y_true: list[int] = []
        y_pred: list[int] = []
        latencies_sec: list[float] = []
        sensitive_traffic_flags: list[int] = []
        unencrypted_sensitive_ratios: list[float] = []
        flow_size_bits: list[int] = []
        traffic_breakdown_bytes = {
            "plaintext_nonsensitive": 0,
            "ciphertext_sensitive": 0,
        }

        sensitive_traffic_idx = select_sensitive_traffic_indices(
            total_count=len(sampled_df),
            ratio_percent=ratio_percent,
            seed=seed + ratio_percent,
        )

        for idx, row in sampled_df.iterrows():
            record = to_internal_record(row)
            is_sensitive_traffic = idx in sensitive_traffic_idx
            sensitive_fields = set(feature_sensitivity_classifier.sensitive_indices(record)) if is_sensitive_traffic else set()

            start = time.perf_counter()
            if remote_helpers is not None:
                # Remote mode: encode → encrypt → remote infer → decrypt
                rh = remote_helpers
                enable_he = (
                    inference_mode == "ckks"
                    or (inference_mode == "mixed" and is_sensitive_traffic)
                )
                encoded = rh["encoder"].encode(record)
                payload = rh["adaptive_module"].protect(
                    x={k: float(v) for k, v in encoded.items() if k != "anomaly"},
                    flag=enable_he,
                    sensitive_idx=list(sensitive_fields),
                )
                z = server.infer(payload)
                decision = rh["client_decision"].decide(z, payload, enable_he)
                prob = decision.prob
                encrypted_feature_list = sorted(payload.get("encrypted", {}).keys())
            elif inference_mode == "ckks":
                prob, _, encrypted_feature_list = server.predict_proba_ckks(record=record, sensitive_fields=sensitive_fields)
            elif inference_mode == "mixed":
                if is_sensitive_traffic:
                    prob, _, encrypted_feature_list = server.predict_proba_ckks(record=record, sensitive_fields=sensitive_fields)
                else:
                    prob = float(server.predict_proba_plain(record))
                    encrypted_feature_list = []
            else:
                prob = float(server.predict_proba_plain(record))
                encrypted_feature_list = []

            encrypted_set = set(encrypted_feature_list)
            if is_sensitive_traffic and len(sensitive_fields) > 0:
                unencrypted_sensitive_count = len(sensitive_fields - encrypted_set)
                unencrypted_sensitive_ratio = unencrypted_sensitive_count / float(len(sensitive_fields))
            else:
                unencrypted_sensitive_ratio = 0.0

            pred = int(prob >= DEFAULT_THRESHOLD)
            latency_sec = time.perf_counter() - start

            row_breakdown = calc_traffic_breakdown_bytes(
                record=record,
                sensitive_fields=sensitive_fields,
                encrypted_fields=encrypted_feature_list,
            )

            label = int(row["Anomaly"])
            y_true.append(label)
            y_pred.append(pred)
            latencies_sec.append(latency_sec)
            sensitive_traffic_flags.append(int(is_sensitive_traffic))
            unencrypted_sensitive_ratios.append(float(unencrypted_sensitive_ratio))
            flow_size_bits.append(calc_flow_size_bits(record))
            for key in traffic_breakdown_bytes:
                traffic_breakdown_bytes[key] += row_breakdown[key]

        y_true_arr = np.asarray(y_true, dtype=np.int64)
        y_pred_arr = np.asarray(y_pred, dtype=np.int64)
        latency_arr = np.asarray(latencies_sec, dtype=np.float64)

        accuracy = float(accuracy_score(y_true_arr, y_pred_arr))
        n_flows = int(len(sampled_df))
        p_sensitive = float(ratio_percent) / 100.0
        unencrypted_sensitive_ratio = (
            float(np.mean(np.asarray(unencrypted_sensitive_ratios, dtype=np.float64)))
            if unencrypted_sensitive_ratios
            else 0.0
        )
        l_flow_size = float(np.mean(np.asarray(flow_size_bits, dtype=np.float64))) if flow_size_bits else 0.0
        d_latency = float(latency_arr.mean()) if len(latency_arr) else 0.0
        lt_information_leakage_kb = float((n_flows * p_sensitive * l_flow_size) / BITS_PER_KB)

        d_latency_eff = max(d_latency, EFFICIENCY_EPSILON)
        lt_eff = max(lt_information_leakage_kb, EFFICIENCY_EPSILON)
        detection_efficiency = float(accuracy / (d_latency_eff * lt_eff))

        rows.append(
            {
                "privacy_sensitive_data_ratio": float(ratio_percent),
                "accuracy": accuracy,
                "latency_sec": d_latency,
                "information_leakage": lt_information_leakage_kb,
                "unencrypted_sensitive_ratio": unencrypted_sensitive_ratio,
                "detection_efficiency": detection_efficiency,
                "plaintext_nonsensitive_bytes": float(traffic_breakdown_bytes["plaintext_nonsensitive"]),
                "ciphertext_sensitive_bytes": float(traffic_breakdown_bytes["ciphertext_sensitive"]),
            }
        )

        print(
            "[ratio={}%] 明文/非敏感={} bytes, 密文/敏感={} bytes".format(
                ratio_percent,
                traffic_breakdown_bytes["plaintext_nonsensitive"],
                traffic_breakdown_bytes["ciphertext_sensitive"],
            )
        )

    sweep_df = pd.DataFrame(rows).sort_values("privacy_sensitive_data_ratio").reset_index(drop=True)
    plot_dir = output_dir / "privacy_ratio_plots"
    plot_dir.mkdir(parents=True, exist_ok=True)

    metrics_csv_path = plot_dir / "appad_metrics_vs_privacy_ratio.csv"
    sweep_df.to_csv(metrics_csv_path, index=False)

    x_values = sweep_df["privacy_sensitive_data_ratio"].astype(int).tolist()
    _plot_metric(
        x_values=x_values,
        y_values=sweep_df["accuracy"].tolist(),
        y_label="Accuracy",
        output_path=plot_dir / "appad_accuracy_vs_privacy_ratio.png",
        y_limits=(0.0, 1.0),
    )
    _plot_metric(
        x_values=x_values,
        y_values=sweep_df["latency_sec"].tolist(),
        y_label="Latency (sec)",
        output_path=plot_dir / "appad_latency_vs_privacy_ratio.png",
    )
    _plot_metric(
        x_values=x_values,
        y_values=sweep_df["information_leakage"].tolist(),
        y_label="Information Leakage (kb)",
        output_path=plot_dir / "appad_information_leakage_vs_privacy_ratio.png",
    )
    _plot_metric(
        x_values=x_values,
        y_values=sweep_df["detection_efficiency"].tolist(),
        y_label="Detection Efficiency",
        output_path=plot_dir / "appad_detection_efficiency_vs_privacy_ratio.png",
    )

    summary = {
        "sample_size": int(len(sampled_df)),
        "privacy_ratios": x_values,
        "inference_mode": inference_mode,
        "metrics_csv": str(metrics_csv_path),
    }
    summary_path = plot_dir / "appad_privacy_ratio_plot_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print("Privacy-ratio sweep complete.")
    print(f"Sweep metrics CSV saved to: {metrics_csv_path}")
    print(f"Sweep summary saved to: {summary_path}")


def run_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    if args.sample_size <= 0:
        raise ValueError("sample_size must be > 0")

    dataset_path = Path(args.dataset_path)
    model_path = Path(args.model_path)
    output_dir = Path(args.output_dir)

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    remote_mode = bool(getattr(args, "server_url", None))

    if remote_mode:
        from adaptive_module.core.adaptive_module import AdaptiveModule
        from adaptive_routing.feature_encoder import SimpleRecordEncoder
        from ckks_homomorphic_encryption.he_encryptor import CKKSEncryptor
        from decision_module.client_decision import ClientDecision
        from server_module.remote_server import RemoteLRModelServer

        encryptor = CKKSEncryptor()
        adaptive_module = AdaptiveModule(encryptor=encryptor)
        client_decision = ClientDecision(encryptor=encryptor, threshold=DEFAULT_THRESHOLD)
        record_encoder = SimpleRecordEncoder()
        server = RemoteLRModelServer(
            base_url=args.server_url,
            ckks_context=encryptor.context,
        )
    else:
        server = LRModelServer(
            model_path=model_path,
            auto_train_if_missing=args.auto_train_if_missing,
        )

    df = pd.read_csv(dataset_path)
    if "Anomaly" not in df.columns:
        raise KeyError("Dataset must include 'Anomaly' column for metric calculation")

    feature_scale_ok, feature_scale_stats = check_feature_scale_consistency(df, MODEL_FEATURE_COLS)
    if not feature_scale_ok and not args.allow_unscaled_dataset:
        raise ValueError(
            "Feature scale consistency check failed: model expects normalized features in [0,1]. "
            f"Dataset appears unscaled or incompatible: {dataset_path}. "
            "Use normalized dataset (e.g. data_preprocessing/output/normalize/test_normalized.csv) "
            "or pass --allow-unscaled-dataset to override intentionally. "
            f"stats={feature_scale_stats}"
        )

    sample_n = min(args.sample_size, len(df))
    sampled_with_source_idx = df.sample(n=sample_n, random_state=args.seed)
    source_row_idx = sampled_with_source_idx.index.to_numpy(dtype=np.int64)
    sampled_df = sampled_with_source_idx.reset_index(drop=True)

    sampled_plain_df = sampled_df.copy()
    sampled_plain_df.insert(0, "sample_idx", np.arange(sample_n, dtype=np.int64))
    sampled_plain_df.insert(1, "source_row_idx", source_row_idx)
    sampled_plain_df["pre_sensitive_label"] = sampled_plain_df.apply(get_pre_sensitive_label, axis=1)

    if (sampled_plain_df["pre_sensitive_label"] == "未知").all() and DEFAULT_PRE_SENSITIVE_SIDECAR.exists():
        try:
            sidecar_df = pd.read_csv(DEFAULT_PRE_SENSITIVE_SIDECAR)
            sidecar_col = infer_sidecar_label_column(sidecar_df)
            if sidecar_col and len(sidecar_df) >= len(df):
                sampled_plain_df["pre_sensitive_label"] = sampled_plain_df["source_row_idx"].apply(
                    lambda i: _to_pre_sensitive_label(sidecar_df.iloc[int(i)][sidecar_col])
                )
        except Exception:
            pass

    classifier = SensitivityClassifier()
    feature_sensitivity_classifier = FeatureSensitivityClassifier()
    privacy_ratios = parse_ratio_list(args.privacy_ratios)

    effective_mode = args.inference_mode
    if not remote_mode and effective_mode in {"ckks", "mixed"}:
        try:
            _ = server.ckks_model
        except Exception as exc:
            if args.allow_plaintext_fallback:
                effective_mode = "plaintext"
                print(f"[WARN] CKKS unavailable; fallback to plaintext: {exc}")
            else:
                raise

    y_true: list[int] = []
    y_pred: list[int] = []
    latencies_sec: list[float] = []
    sensitive_traffic_flags: list[int] = []
    unencrypted_sensitive_ratios: list[float] = []
    flow_size_bits: list[int] = []
    traffic_breakdown_bytes = {
        "plaintext_nonsensitive": 0,
        "ciphertext_sensitive": 0,
    }
    rows: list[dict[str, Any]] = []
    encrypted_payload_rows: list[dict[str, Any]] = []

    for idx, row in sampled_df.iterrows():
        record = to_internal_record(row)
        start = time.perf_counter()

        sensitivity = classifier.classify(record)
        sensitive_fields = set(feature_sensitivity_classifier.sensitive_indices(record))

        if remote_mode:
            # Remote mode: encode → encrypt locally → infer remotely → decrypt locally
            enable_he = (
                effective_mode == "ckks"
                or (effective_mode == "mixed" and bool(sensitivity["encryption_required"]))
            )
            encoded = record_encoder.encode(record)
            payload = adaptive_module.protect(
                x={k: float(v) for k, v in encoded.items() if k != "anomaly"},
                flag=enable_he,
                sensitive_idx=list(sensitive_fields),
            )
            z = server.infer(payload)
            decision = client_decision.decide(z, payload, enable_he)
            prob = decision.prob
            encrypted_feature_list = sorted(payload.get("encrypted", {}).keys())
            if effective_mode == "ckks":
                detection_path = "ckks_privacy_inference"
            elif enable_he:
                detection_path = "mixed_privacy_inference"
            else:
                detection_path = "plaintext_inference"
            encrypted_payload = {}
        elif effective_mode == "ckks":
            prob, _, encrypted_feature_list, encrypted_payload = server.predict_proba_ckks(
                record=record,
                sensitive_fields=sensitive_fields,
                capture_encrypted_payload=True,
            )
            detection_path = "ckks_privacy_inference"
        elif effective_mode == "mixed":
            # In mixed mode, tie encryption behavior to sensitivity judgement:
            # HIGH (encryption_required=True) -> CKKS; otherwise -> plaintext.
            if bool(sensitivity["encryption_required"]):
                prob, _, encrypted_feature_list, encrypted_payload = server.predict_proba_ckks(
                    record=record,
                    sensitive_fields=sensitive_fields,
                    capture_encrypted_payload=True,
                )
                detection_path = "mixed_privacy_inference"
            else:
                prob = float(server.predict_proba_plain(record))
                encrypted_feature_list = []
                encrypted_payload = {}
                detection_path = "plaintext_inference"
        else:
            prob = float(server.predict_proba_plain(record))
            encrypted_feature_list = []
            encrypted_payload = {}
            detection_path = "plaintext_inference"

        is_sensitive_traffic = bool(sensitivity["is_sensitive"])
        encrypted_set = set(encrypted_feature_list)
        unencrypted_sensitive_fields = sorted(list(sensitive_fields - encrypted_set))
        if is_sensitive_traffic and len(sensitive_fields) > 0:
            unencrypted_sensitive_ratio = len(unencrypted_sensitive_fields) / float(len(sensitive_fields))
        else:
            unencrypted_sensitive_ratio = 0.0
        row_breakdown = calc_traffic_breakdown_bytes(
            record=record,
            sensitive_fields=sensitive_fields,
            encrypted_fields=encrypted_feature_list,
        )

        pred = int(prob >= DEFAULT_THRESHOLD)
        latency_sec = time.perf_counter() - start

        label = int(row["Anomaly"])
        y_true.append(label)
        y_pred.append(pred)
        latencies_sec.append(latency_sec)
        sensitive_traffic_flags.append(int(is_sensitive_traffic))
        unencrypted_sensitive_ratios.append(float(unencrypted_sensitive_ratio))
        flow_size_bits.append(calc_flow_size_bits(record))
        for key in traffic_breakdown_bytes:
            traffic_breakdown_bytes[key] += row_breakdown[key]

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
                "unencrypted_sensitive_fields": "|".join(unencrypted_sensitive_fields),
                "unencrypted_sensitive_field_count": len(unencrypted_sensitive_fields),
                "unencrypted_sensitive_ratio": round(unencrypted_sensitive_ratio, 4),
                "latency_sec": round(latency_sec, 6),
                "reasons": "|".join(sensitivity["reasons"]),
            }
        )

        if encrypted_payload:
            payload_files: dict[str, Any] = {}
            for field_name, ciphertext_obj in encrypted_payload.items():
                bin_name = f"sample_{int(idx):06d}__{_safe_name(field_name)}.bin"
                bin_path = output_dir / f"appad_pre_inference_ciphertexts_{effective_mode}" / bin_name
                bytes_len = persist_raw_ciphertext(ciphertext_obj, bin_path)
                payload_files[field_name] = {
                    "encoding": "raw_ckks_serialized_bytes",
                    "file": str(bin_path),
                    "bytes": bytes_len,
                }

            encrypted_payload_rows.append(
                {
                    "sample_idx": int(idx),
                    "detection_path": detection_path,
                    "sensitivity_level": sensitivity["sensitivity_level"],
                    "encrypted_fields": sorted(list(encrypted_payload.keys())),
                    "payload": payload_files,
                }
            )

    y_true_arr = np.asarray(y_true, dtype=np.int64)
    y_pred_arr = np.asarray(y_pred, dtype=np.int64)
    latency_arr = np.asarray(latencies_sec, dtype=np.float64)

    accuracy = float(accuracy_score(y_true_arr, y_pred_arr))
    precision = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    recall = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))

    n_flows = int(sample_n)
    p_sensitive = FIXED_P_SENSITIVE
    unencrypted_sensitive_ratio = (
        float(np.mean(np.asarray(unencrypted_sensitive_ratios, dtype=np.float64)))
        if unencrypted_sensitive_ratios
        else 0.0
    )
    l_flow_size = float(np.mean(np.asarray(flow_size_bits, dtype=np.float64))) if flow_size_bits else 0.0
    d_latency = float(latency_arr.mean()) if len(latency_arr) else 0.0
    lt_information_leakage_kb = float((n_flows * p_sensitive * l_flow_size) / BITS_PER_KB)

    d_latency_eff = max(d_latency, EFFICIENCY_EPSILON)
    lt_eff = max(lt_information_leakage_kb, EFFICIENCY_EPSILON)
    detection_efficiency = float(accuracy / (d_latency_eff * lt_eff))

    results = {
        "config": {
            "dataset_path": str(dataset_path),
            "model_path": str(model_path),
            "sample_size_requested": int(args.sample_size),
            "sample_size_actual": int(sample_n),
            "seed": int(args.seed),
            "threshold": DEFAULT_THRESHOLD,
            "inference_mode_requested": args.inference_mode,
            "inference_mode_used": effective_mode,
            "feature_scale_check_passed": bool(feature_scale_ok),
            "allow_unscaled_dataset": bool(args.allow_unscaled_dataset),
        },
        "metrics": {
            "accuracy": round(accuracy, 4),
            "detection_efficiency": round(detection_efficiency, 8),
            "information_leakage": round(lt_information_leakage_kb, 6),
            "information_leakage_unit": "kb",
            "unencrypted_sensitive_ratio": round(unencrypted_sensitive_ratio, 6),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "formula_terms": {
            "N": n_flows,
            "p": round(p_sensitive, 6),
            "l": round(l_flow_size, 4),
            "l_unit": "bits",
            "d": round(d_latency, 6),
            "Lt": round(lt_information_leakage_kb, 6),
            "Lt_unit": "kb",
            "definition": "detection_efficiency = accuracy / (d * Lt), Lt = (N * p * l_bits) / 1000 (p is fixed at 0.5)",
        },
        "latency_sec": {
            "avg": round(float(latency_arr.mean()), 4),
            "max": round(float(latency_arr.max()), 4),
            "min": round(float(latency_arr.min()), 4),
        },
        "traffic_breakdown_bytes": {
            "plaintext_nonsensitive": int(traffic_breakdown_bytes["plaintext_nonsensitive"]),
            "ciphertext_sensitive": int(traffic_breakdown_bytes["ciphertext_sensitive"]),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    pred_path = output_dir / f"appad_main_predictions_{effective_mode}.csv"
    metrics_path = output_dir / f"appad_main_metrics_{effective_mode}.json"
    encrypted_payload_path = output_dir / f"appad_pre_inference_encrypted_payloads_{effective_mode}.jsonl"
    encrypted_bin_dir = output_dir / f"appad_pre_inference_ciphertexts_{effective_mode}"
    sampled_plain_path = output_dir / f"appad_sampled_plain_{effective_mode}.csv"

    pd.DataFrame(rows).to_csv(pred_path, index=False)
    sampled_plain_df.to_csv(sampled_plain_path, index=False)

    if encrypted_payload_rows:
        with encrypted_payload_path.open("w", encoding="utf-8") as f:
            for row in encrypted_payload_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    else:
        if encrypted_payload_path.exists():
            encrypted_payload_path.unlink()
        if encrypted_bin_dir.exists():
            for item in encrypted_bin_dir.glob("*.bin"):
                item.unlink()

    results["config"]["pre_inference_encrypted_payload_path"] = str(encrypted_payload_path) if encrypted_payload_rows else ""
    results["config"]["pre_inference_encrypted_payload_count"] = int(len(encrypted_payload_rows))
    results["config"]["pre_inference_encrypted_ciphertext_dir"] = str(encrypted_bin_dir) if encrypted_payload_rows else ""
    results["config"]["sampled_plain_data_path"] = str(sampled_plain_path)

    with metrics_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("APPAD pipeline complete.")
    print(f"Predictions saved to: {pred_path}")
    print(f"Metrics saved to: {metrics_path}")
    print(
        "Accuracy={:.4f}, Information Leakage(Lt, kb)={:.4f}, Detection Efficiency={:.4f}, Avg Latency(sec)={:.4f}".format(
            results["metrics"]["accuracy"],
            results["metrics"]["information_leakage"],
            results["metrics"]["detection_efficiency"],
            results["latency_sec"]["avg"],
        )
    )
    print(
        "流量分類(bytes) -> 明文/非敏感={}, 密文/敏感={}".format(
            results["traffic_breakdown_bytes"]["plaintext_nonsensitive"],
            results["traffic_breakdown_bytes"]["ciphertext_sensitive"],
        )
    )

    if not args.skip_privacy_ratio_sweep:
        rh = None
        if remote_mode:
            rh = {
                "encoder": record_encoder,
                "adaptive_module": adaptive_module,
                "client_decision": client_decision,
            }
        run_privacy_ratio_sweep(
            sampled_df=sampled_df,
            privacy_ratios=privacy_ratios,
            seed=args.seed,
            inference_mode=effective_mode,
            server=server,
            feature_sensitivity_classifier=feature_sensitivity_classifier,
            output_dir=output_dir,
            remote_helpers=rh,
        )

    return results


def cli_main(argv: list[str] | None = None) -> dict[str, Any]:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_pipeline(args)
