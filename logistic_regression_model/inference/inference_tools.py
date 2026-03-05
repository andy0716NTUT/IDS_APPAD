from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


FEATURE_COLS = ["User ID", "Session Duration", "Failed Attempts", "Behavioral Score"]
TARGET_COL = "Anomaly"


def resolve_data_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data_preprocessing" / "output" / "normalize"


def resolve_model_path() -> Path:
    return Path(__file__).resolve().parents[1] / "output_lr" / "lr_model.joblib"


def load_trained_model(model_path: Path):
    return joblib.load(model_path)


def predict_probabilities(model, df: pd.DataFrame) -> np.ndarray:
    X = df[FEATURE_COLS].values.astype(np.float32)
    return model.predict_proba(X)[:, 1]
