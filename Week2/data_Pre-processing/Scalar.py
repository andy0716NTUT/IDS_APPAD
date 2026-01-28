from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Tuple
import os

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def resolve_default_input() -> Path:
	base_dir = Path(__file__).resolve().parents[2]
	return base_dir / "dataset" / "synthetic_web_auth_logs.csv"


def split_data(
	df: pd.DataFrame,
	train_ratio: float,
	val_ratio: float,
	seed: int,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
	if train_ratio <= 0 or val_ratio <= 0 or train_ratio + val_ratio >= 1:
		raise ValueError("train_ratio and val_ratio must be > 0 and sum < 1.")

	train_df, temp_df = train_test_split(
		df,
		test_size=1 - train_ratio,
		random_state=seed,
		shuffle=True,
	)

	val_size = val_ratio / (1 - train_ratio)
	val_df, test_df = train_test_split(
		temp_df,
		test_size=1 - val_size,
		random_state=seed,
		shuffle=True,
	)

	return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def get_numeric_columns(df: pd.DataFrame, columns_arg: str | None) -> List[str]:
	if columns_arg:
		cols = [c.strip() for c in columns_arg.split(",") if c.strip()]
		missing = [c for c in cols if c not in df.columns]
		if missing:
			raise ValueError(f"Columns not found in dataset: {missing}")
		return cols

	return df.select_dtypes(include="number").columns.tolist()


def main() -> None:
	parser = argparse.ArgumentParser(description="Standardize dataset using training set only.")
	parser.add_argument("--input", type=str, default=str(resolve_default_input()), help="Input CSV path")
	parser.add_argument("--output-dir", type=str, default=str(Path(__file__).parent / "output" / "standard"))
	parser.add_argument("--train-ratio", type=float, default=0.7)
	parser.add_argument("--val-ratio", type=float, default=0.15)
	parser.add_argument("--seed", type=int, default=42)
	parser.add_argument("--columns", type=str, default=None, help="Comma-separated numeric columns to standardize")
	args = parser.parse_args()

	input_path = Path(args.input)
	if not input_path.exists():
		raise FileNotFoundError(f"Input file not found: {input_path}")

	df = pd.read_csv(input_path)
	numeric_cols = get_numeric_columns(df, args.columns)
	if not numeric_cols:
		raise ValueError("No numeric columns found to standardize.")

	train_df, val_df, test_df = split_data(df, args.train_ratio, args.val_ratio, args.seed)

	scaler = StandardScaler()
	scaler.fit(train_df[numeric_cols])

	def apply_scaler(frame: pd.DataFrame) -> pd.DataFrame:
		out = frame.copy()
		out[numeric_cols] = scaler.transform(frame[numeric_cols])
		return out

	train_scaled = apply_scaler(train_df)
	val_scaled = apply_scaler(val_df)
	test_scaled = apply_scaler(test_df)

	output_dir = Path(args.output_dir)
	output_dir.mkdir(parents=True, exist_ok=True)

	train_path = output_dir / "train_standardized.csv"
	val_path = output_dir / "val_standardized.csv"
	test_path = output_dir / "test_standardized.csv"

	train_scaled.to_csv(train_path, index=False)
	val_scaled.to_csv(val_path, index=False)
	test_scaled.to_csv(test_path, index=False)

	params = {
		"scaler": "StandardScaler",
		"columns": numeric_cols,
		"mean": scaler.mean_.tolist(),
		"scale": scaler.scale_.tolist(),
		"var": scaler.var_.tolist(),
		"train_ratio": args.train_ratio,
		"val_ratio": args.val_ratio,
		"seed": args.seed,
		"input": os.path.relpath(input_path, start=Path(__file__).resolve().parents[2])
	}

	with (output_dir / "standard_params.json").open("w", encoding="utf-8") as f:
		json.dump(params, f, ensure_ascii=False, indent=2)

	print("Standardization complete.")
	print(f"Train: {train_path}")
	print(f"Val:   {val_path}")
	print(f"Test:  {test_path}")
	print("Params:")
	print(json.dumps(params, ensure_ascii=False, indent=2))


if __name__ == "__main__":
	main()
