from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, precision_recall_curve


def load_data(csv_path: Path, feature_cols: list[str], target_col: str) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    X = df[feature_cols].values.astype(np.float32)
    y = df[target_col].values.astype(np.int64)
    return X, y


def evaluate(y_true: np.ndarray, y_probs: np.ndarray, threshold: float) -> dict:
    y_pred = (y_probs >= threshold).astype(int)
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def plot_metrics_summary(train_metrics: dict, val_metrics: dict, test_metrics: dict, output_path: Path) -> None:
    metrics = ["accuracy", "precision", "recall", "f1"]
    train_values = [train_metrics[m] for m in metrics]
    val_values = [val_metrics[m] for m in metrics]
    test_values = [test_metrics[m] for m in metrics]

    x = np.arange(len(metrics))
    width = 0.25

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - width, train_values, width, label="Train")
    ax.bar(x, val_values, width, label="Val")
    ax.bar(x + width, test_values, width, label="Test")

    ax.set_xticks(x)
    ax.set_xticklabels([m.title() for m in metrics])
    ax.set_ylim(0, 1)
    ax.set_ylabel("Score")
    ax.set_title("LR Metrics Summary")
    ax.legend(loc="lower right")
    ax.grid(True, axis="y", alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_pr_curve(y_true: np.ndarray, y_probs: np.ndarray, output_path: Path) -> None:
    precision, recall, _ = precision_recall_curve(y_true, y_probs)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(recall, precision, color="blue", linewidth=2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve (Validation)")
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1])
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


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


def resolve_data_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data_preprocessing" / "output" / "normalize"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Logistic Regression on normalized data")
    parser.add_argument("--data-dir", type=str, default=str(resolve_data_dir()))
    parser.add_argument("--output-dir", type=str, default=str(Path(__file__).resolve().parents[1] / "output_lr"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-iter", type=int, default=10, help="Training iterations (paper used 10)")
    parser.add_argument("--use-class-weight", action="store_true", help="Use balanced class weights")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    feature_cols = ["User ID", "Session Duration", "Failed Attempts", "Behavioral Score"]
    target_col = "Anomaly"

    # Load data
    X_train, y_train = load_data(data_dir / "train_normalized.csv", feature_cols, target_col)
    X_val, y_val = load_data(data_dir / "val_normalized.csv", feature_cols, target_col)
    X_test, y_test = load_data(data_dir / "test_normalized.csv", feature_cols, target_col)

    # Train LR model
    class_weight = "balanced" if args.use_class_weight else None
    model = LogisticRegression(
        max_iter=args.max_iter,
        class_weight=class_weight,
        solver="lbfgs",
    )
    model.fit(X_train, y_train)

    # Inference (probabilities for class 1)
    train_probs = model.predict_proba(X_train)[:, 1]
    val_probs = model.predict_proba(X_val)[:, 1]
    test_probs = model.predict_proba(X_test)[:, 1]

    train_metrics = evaluate(y_train, train_probs, args.threshold)
    val_metrics = evaluate(y_val, val_probs, args.threshold)
    test_metrics = evaluate(y_test, test_probs, args.threshold)

    results = {
        "config": {
            "max_iter": args.max_iter,
            "threshold": args.threshold,
            "use_class_weight": args.use_class_weight,
            "feature_cols": feature_cols,
            "target_col": target_col,
        },
        "train_metrics": train_metrics,
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    with (output_dir / "training_results_lr.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    joblib.dump(model, output_dir / "lr_model.joblib")

    plot_metrics_summary(
        train_metrics,
        val_metrics,
        test_metrics,
        output_dir / "training_metrics_lr.png",
    )
    plot_pr_curve(y_val, val_probs, output_dir / "precision_recall_curve_lr.png")
    plot_confusion_matrix(
        val_metrics["confusion_matrix"],
        output_dir / "val_confusion_matrix_lr.png",
        "Validation Confusion Matrix",
    )
    plot_confusion_matrix(
        test_metrics["confusion_matrix"],
        output_dir / "test_confusion_matrix_lr.png",
        "Test Confusion Matrix",
    )

    print("Logistic Regression training complete.")
    print(f"Results saved to: {output_dir / 'training_results_lr.json'}")
    print(f"Model saved to: {output_dir / 'lr_model.joblib'}")


if __name__ == "__main__":
    main()
