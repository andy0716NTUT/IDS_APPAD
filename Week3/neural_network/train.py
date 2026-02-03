from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, precision_recall_curve
import matplotlib.pyplot as plt


def get_predictions(model: nn.Module, dataloader: DataLoader, device: torch.device) -> tuple[np.ndarray, np.ndarray]:
    """Get all predictions and labels from dataloader."""
    model.eval()
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for X_batch, y_batch in dataloader:
            X_batch = X_batch.to(device)
            outputs = model(X_batch)
            all_probs.extend(outputs.cpu().numpy().flatten())
            all_labels.extend(y_batch.numpy().flatten())

    return np.array(all_probs), np.array(all_labels)


def plot_precision_recall_curve(y_true: np.ndarray, y_scores: np.ndarray, output_path: Path) -> dict:
    """Plot precision-recall curve and save to file."""
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)

    # Calculate F1 for each threshold
    f1_scores = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-8)
    best_idx = np.argmax(f1_scores)
    best_threshold = thresholds[best_idx]
    best_f1 = f1_scores[best_idx]

    # Create figure with two subplots
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Plot 1: Precision-Recall Curve
    axes[0].plot(recall, precision, 'b-', linewidth=2)
    axes[0].scatter(recall[best_idx], precision[best_idx], color='red', s=100, zorder=5,
                    label=f'Best F1={best_f1:.3f} @ threshold={best_threshold:.3f}')
    axes[0].set_xlabel('Recall', fontsize=12)
    axes[0].set_ylabel('Precision', fontsize=12)
    axes[0].set_title('Precision-Recall Curve', fontsize=14)
    axes[0].legend(loc='lower left')
    axes[0].grid(True, alpha=0.3)
    axes[0].set_xlim([0, 1])
    axes[0].set_ylim([0, 1])

    # Plot 2: Metrics vs Threshold
    axes[1].plot(thresholds, precision[:-1], 'b-', label='Precision', linewidth=2)
    axes[1].plot(thresholds, recall[:-1], 'g-', label='Recall', linewidth=2)
    axes[1].plot(thresholds, f1_scores, 'r-', label='F1 Score', linewidth=2)
    axes[1].axvline(x=best_threshold, color='gray', linestyle='--', alpha=0.7,
                    label=f'Best threshold={best_threshold:.3f}')
    axes[1].set_xlabel('Threshold', fontsize=12)
    axes[1].set_ylabel('Score', fontsize=12)
    axes[1].set_title('Metrics vs Threshold', fontsize=14)
    axes[1].legend(loc='center right')
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xlim([0, 1])
    axes[1].set_ylim([0, 1])

    plt.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close(fig)

    # Return threshold analysis
    threshold_analysis = []
    for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7]:
        idx = np.searchsorted(thresholds, t)
        if idx < len(precision) - 1:
            threshold_analysis.append({
                "threshold": t,
                "precision": float(precision[idx]),
                "recall": float(recall[idx]),
                "f1": float(f1_scores[idx]) if idx < len(f1_scores) else 0.0
            })

    return {
        "best_threshold": float(best_threshold),
        "best_f1": float(best_f1),
        "best_precision": float(precision[best_idx]),
        "best_recall": float(recall[best_idx]),
        "threshold_analysis": threshold_analysis
    }


class AnomalyDetector(nn.Module):
    """Simple feedforward neural network for anomaly detection."""

    def __init__(self, input_dim: int, hidden_dims: list[int] = None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [32, 16]

        layers = []
        prev_dim = input_dim
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
            ])
            prev_dim = hidden_dim

        layers.append(nn.Linear(prev_dim, 1))
        layers.append(nn.Sigmoid())

        self.network = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


def load_data(csv_path: Path, feature_cols: list[str], target_col: str) -> tuple[np.ndarray, np.ndarray]:
    """Load CSV and extract features and target."""
    df = pd.read_csv(csv_path)
    X = df[feature_cols].values.astype(np.float32)
    y = df[target_col].values.astype(np.float32)
    return X, y


def create_dataloader(X: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool = True) -> DataLoader:
    """Create PyTorch DataLoader from numpy arrays."""
    X_tensor = torch.from_numpy(X)
    y_tensor = torch.from_numpy(y).unsqueeze(1)
    dataset = TensorDataset(X_tensor, y_tensor)
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle)


def train_epoch(model: nn.Module, dataloader: DataLoader, criterion: nn.Module,
                optimizer: torch.optim.Optimizer, device: torch.device) -> float:
    """Train for one epoch and return average loss."""
    model.train()
    total_loss = 0.0

    for X_batch, y_batch in dataloader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)

        optimizer.zero_grad()
        outputs = model(X_batch)
        loss = criterion(outputs, y_batch)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * X_batch.size(0)

    return total_loss / len(dataloader.dataset)


def evaluate(model: nn.Module, dataloader: DataLoader, criterion: nn.Module,
             device: torch.device, threshold: float = 0.5) -> dict:
    """Evaluate model and return metrics."""
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []
    total_loss = 0.0

    with torch.no_grad():
        for X_batch, y_batch in dataloader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            total_loss += loss.item() * X_batch.size(0)

            all_probs.extend(outputs.cpu().numpy().flatten())
            preds = (outputs >= threshold).float()
            all_preds.extend(preds.cpu().numpy().flatten())
            all_labels.extend(y_batch.cpu().numpy().flatten())

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    return {
        "loss": total_loss / len(dataloader.dataset),
        "accuracy": accuracy_score(all_labels, all_preds),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
        "confusion_matrix": confusion_matrix(all_labels, all_preds).tolist(),
    }


def resolve_data_dir() -> Path:
    """Resolve path to normalized data directory."""
    return Path(__file__).resolve().parents[2] / "Week2" / "data_Pre-processing" / "output" / "normalize"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train neural network on normalized data")
    parser.add_argument("--data-dir", type=str, default=str(resolve_data_dir()))
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=0.001)
    parser.add_argument("--hidden-dims", type=str, default="32,16", help="Comma-separated hidden layer dimensions")
    parser.add_argument("--output-dir", type=str, default=str(Path(__file__).parent / "output"))
    parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold (lower = higher recall)")
    parser.add_argument("--use-class-weight", action="store_true", help="Use class weights to handle imbalance")
    args = parser.parse_args()

    # Setup
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Feature columns (numeric columns except target)
    feature_cols = ["User ID", "Session Duration", "Failed Attempts", "Behavioral Score"]
    target_col = "Anomaly"

    # Load data
    print("Loading data...")
    X_train, y_train = load_data(data_dir / "train_normalized.csv", feature_cols, target_col)
    X_val, y_val = load_data(data_dir / "val_normalized.csv", feature_cols, target_col)

    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_val)}")
    print(f"Anomaly ratio (train): {y_train.mean():.2%}")

    # Create dataloaders
    train_loader = create_dataloader(X_train, y_train, args.batch_size, shuffle=True)
    val_loader = create_dataloader(X_val, y_val, args.batch_size, shuffle=False)

    # Create model
    hidden_dims = [int(x) for x in args.hidden_dims.split(",")]
    model = AnomalyDetector(input_dim=len(feature_cols), hidden_dims=hidden_dims)
    model.to(device)
    print(f"Model architecture: {len(feature_cols)} -> {hidden_dims} -> 1")

    # Loss and optimizer with optional class weighting
    if args.use_class_weight:
        pos_weight = (1 - y_train.mean()) / y_train.mean()  # ~4.6 for 17.9% anomaly
        print(f"Using class weight (pos_weight): {pos_weight:.2f}")

        def weighted_bce_loss(pred, target):
            weights = torch.where(target == 1, pos_weight, 1.0)
            bce = nn.functional.binary_cross_entropy(pred, target, reduction='none')
            return (bce * weights).mean()
        criterion = weighted_bce_loss
    else:
        criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    # Training loop
    print("\nTraining...")
    best_val_f1 = 0.0
    history = {"train_loss": [], "val_loss": [], "val_accuracy": [], "val_f1": []}

    for epoch in range(args.epochs):
        train_loss = train_epoch(model, train_loader, criterion, optimizer, device)
        val_metrics = evaluate(model, val_loader, criterion, device, args.threshold)

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_metrics["loss"])
        history["val_accuracy"].append(val_metrics["accuracy"])
        history["val_f1"].append(val_metrics["f1"])

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            torch.save(model.state_dict(), output_dir / "best_model.pt")

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"Epoch {epoch+1:3d}/{args.epochs} | "
                  f"Train Loss: {train_loss:.4f} | "
                  f"Val Loss: {val_metrics['loss']:.4f} | "
                  f"Val Acc: {val_metrics['accuracy']:.4f} | "
                  f"Val F1: {val_metrics['f1']:.4f}")

    # Final evaluation
    print("\n" + "=" * 50)
    print(f"Final Validation Results (threshold={args.threshold}):")
    print("=" * 50)

    model.load_state_dict(torch.load(output_dir / "best_model.pt", weights_only=True))
    final_metrics = evaluate(model, val_loader, criterion, device, args.threshold)

    print(f"Accuracy:  {final_metrics['accuracy']:.4f}")
    print(f"Precision: {final_metrics['precision']:.4f}")
    print(f"Recall:    {final_metrics['recall']:.4f}")
    print(f"F1 Score:  {final_metrics['f1']:.4f}")
    print(f"\nConfusion Matrix:")
    cm = final_metrics["confusion_matrix"]
    print(f"  TN: {cm[0][0]:5d}  FP: {cm[0][1]:5d}")
    print(f"  FN: {cm[1][0]:5d}  TP: {cm[1][1]:5d}")

    # Generate Precision-Recall curve
    print("\nGenerating Precision-Recall curve...")
    y_probs, y_true = get_predictions(model, val_loader, device)
    pr_analysis = plot_precision_recall_curve(y_true, y_probs, output_dir / "precision_recall_curve.png")

    print(f"\nPrecision-Recall Analysis:")
    print(f"  Best threshold: {pr_analysis['best_threshold']:.3f}")
    print(f"  Best F1: {pr_analysis['best_f1']:.4f}")
    print(f"  Precision @ best: {pr_analysis['best_precision']:.4f}")
    print(f"  Recall @ best: {pr_analysis['best_recall']:.4f}")

    print("\nThreshold comparison:")
    print(f"  {'Threshold':<10} {'Precision':<10} {'Recall':<10} {'F1':<10}")
    print(f"  {'-'*40}")
    for t in pr_analysis['threshold_analysis']:
        print(f"  {t['threshold']:<10.2f} {t['precision']:<10.4f} {t['recall']:<10.4f} {t['f1']:<10.4f}")

    # Save results
    results = {
        "config": {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.lr,
            "hidden_dims": hidden_dims,
            "feature_cols": feature_cols,
            "target_col": target_col,
            "threshold": args.threshold,
            "use_class_weight": args.use_class_weight,
        },
        "final_metrics": final_metrics,
        "history": history,
        "precision_recall_analysis": pr_analysis,
    }

    with (output_dir / "training_results.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\nModel saved to: {output_dir / 'best_model.pt'}")
    print(f"Results saved to: {output_dir / 'training_results.json'}")
    print(f"PR curve saved to: {output_dir / 'precision_recall_curve.png'}")


if __name__ == "__main__":
    main()
