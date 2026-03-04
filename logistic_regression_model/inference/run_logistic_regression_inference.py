from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


def evaluate(y_true: np.ndarray, y_probs: np.ndarray, threshold: float) -> dict:
    y_pred = (y_probs >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def resolve_data_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data_preprocessing" / "output" / "normalize"


def plot_confusion_matrix(cm: list[list[int]], output_path: Path, title: str) -> None:
    fig, ax = plt.subplots(figsize=(4.8, 4.2))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_title(title)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Anomaly"])
    ax.set_yticklabels(["Normal", "Anomaly"])

    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i][j], ha="center", va="center", color="black")

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_probability_histogram(probs: np.ndarray, output_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.hist(probs, bins=30, color="#4C72B0", alpha=0.85)
    ax.set_title("Inference Probability Distribution")
    ax.set_xlabel("Anomaly Probability")
    ax.set_ylabel("Count")
    ax.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run inference with trained Logistic Regression model")
    parser.add_argument("--model-path", type=str, default=str(Path(__file__).resolve().parents[1] / "output_lr" / "lr_model.joblib"))
    parser.add_argument("--data-path", type=str, default=str(resolve_data_dir() / "test_normalized.csv"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--output-dir", type=str, default=str(Path(__file__).resolve().parents[1] / "output_lr"))
    args = parser.parse_args()

    model_path = Path(args.model_path)
    data_path = Path(args.data_path)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    feature_cols = ["User ID", "Session Duration", "Failed Attempts", "Behavioral Score"]
    target_col = "Anomaly"

    df = pd.read_csv(data_path)
    X = df[feature_cols].values.astype(np.float32)

    model = joblib.load(model_path)
    probs = model.predict_proba(X)[:, 1]
    preds = (probs >= args.threshold).astype(int)

    # Save predictions
    out_df = df.copy()
    out_df["anomaly_prob"] = probs
    out_df["anomaly_pred"] = preds
    pred_path = output_dir / "lr_inference_predictions.csv"
    out_df.to_csv(pred_path, index=False)

    plot_probability_histogram(probs, output_dir / "lr_inference_prob_hist.png")

    # If labels exist, compute metrics
    metrics = None
    if target_col in df.columns:
        y_true = df[target_col].values.astype(np.int64)
        metrics = evaluate(y_true, probs, args.threshold)
        metrics_path = output_dir / "lr_inference_metrics.json"
        with metrics_path.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "data_path": str(data_path),
                    "threshold": args.threshold,
                    "metrics": metrics,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        plot_confusion_matrix(metrics["confusion_matrix"], output_dir / "lr_inference_confusion_matrix.png",
                              "Inference Confusion Matrix")

    print("Inference complete.")
    print(f"Predictions saved to: {pred_path}")
    if metrics is not None:
        print(f"Metrics saved to: {output_dir / 'lr_inference_metrics.json'}")


if __name__ == "__main__":
    main()
