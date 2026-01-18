"""Data preprocessing for UNSW-NB15.

- Drops non-useful identifiers when present.
- Encodes categorical network protocol fields.
- Scales numeric features.
- Persists a processed CSV ready for model training.
- Supports reusing the same fitted transformer for test data (no refit).
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def _resolve_label(df: pd.DataFrame) -> pd.Series:
    """Return binary labels (0 normal, 1 attack) from common UNSW-NB15 columns."""
    if "label" in df.columns:
        return df["label"].astype(int)
    if "attack_cat" in df.columns:
        return (df["attack_cat"].str.lower() != "normal").astype(int)
    raise ValueError("No label or attack_cat column found to derive target labels.")


def _split_features_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    labels = _resolve_label(df)
    feature_drop = [col for col in ("label", "attack_cat", "id", "ids", "Unnamed: 0") if col in df.columns]
    features = df.drop(columns=feature_drop, errors="ignore")
    return features, labels


def _select_columns(df: pd.DataFrame) -> Tuple[List[str], List[str]]:
    """Select categorical (limited) and numeric columns."""
    preferred_cats = [col for col in ("proto", "service", "state") if col in df.columns]
    cat_cols = preferred_cats
    numeric_cols = [
        col
        for col in df.columns
        if col not in cat_cols and pd.api.types.is_numeric_dtype(df[col])
    ]
    return cat_cols, numeric_cols


def _build_preprocessor(cat_cols: List[str], numeric_cols: List[str]) -> ColumnTransformer:
    if not numeric_cols:
        raise ValueError("No numeric columns found after selection; check input schema.")

    transformers = []
    if cat_cols:
        transformers.append(
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                cat_cols,
            )
        )
    transformers.append(("num", StandardScaler(), numeric_cols))
    return ColumnTransformer(transformers=transformers, remainder="drop")


def _get_feature_names(preprocessor: ColumnTransformer, cat_cols: List[str], numeric_cols: List[str]) -> List[str]:
    cat_feature_names: Iterable[str] = []
    if cat_cols:
        enc = preprocessor.named_transformers_["cat"]
        cat_feature_names = enc.get_feature_names_out(cat_cols)
    all_feature_names: List[str] = []
    all_feature_names.extend(cat_feature_names)
    all_feature_names.extend(numeric_cols)
    return list(all_feature_names)


def preprocess_fit(input_csv: Path, output_csv: Path, preprocessor_path: Path) -> Path:
    """Fit the preprocessing pipeline on training data and persist both data and transformer."""
    df = pd.read_csv(input_csv)
    features, labels = _split_features_labels(df)
    cat_cols, numeric_cols = _select_columns(features)

    preprocessor = _build_preprocessor(cat_cols, numeric_cols)
    transformed = preprocessor.fit_transform(features)
    feature_names = _get_feature_names(preprocessor, cat_cols, numeric_cols)

    transformed_df = pd.DataFrame(
        transformed.toarray() if hasattr(transformed, "toarray") else transformed,
        columns=feature_names,
    )
    transformed_df["label"] = labels.values

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    transformed_df.to_csv(output_csv, index=False)

    preprocessor_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "preprocessor": preprocessor,
            "cat_cols": cat_cols,
            "numeric_cols": numeric_cols,
            "feature_names": feature_names,
        },
        preprocessor_path,
    )
    print(f"Saved processed training data to {output_csv}")
    print(f"Saved fitted preprocessor to {preprocessor_path}")
    return output_csv


def preprocess_transform(input_csv: Path, output_csv: Path, preprocessor_path: Path) -> Path:
    """Transform data using an already-fitted preprocessor (no refit)."""
    if not preprocessor_path.exists():
        raise FileNotFoundError(f"Missing pre-fitted preprocessor at {preprocessor_path}")

    bundle = joblib.load(preprocessor_path)
    preprocessor: ColumnTransformer = bundle["preprocessor"]
    feature_names: List[str] = bundle["feature_names"]

    df = pd.read_csv(input_csv)
    features, labels = _split_features_labels(df)

    transformed = preprocessor.transform(features)
    transformed_df = pd.DataFrame(
        transformed.toarray() if hasattr(transformed, "toarray") else transformed,
        columns=feature_names,
    )
    if labels is not None:
        transformed_df["label"] = labels.values

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    transformed_df.to_csv(output_csv, index=False)
    print(f"Saved processed data to {output_csv} using existing preprocessor")
    return output_csv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preprocess UNSW-NB15 dataset for hybrid IDS.")
    parser.add_argument("--input", type=Path, default=Path("data/raw/UNSW_NB15_training-set.csv"), help="Path to raw UNSW-NB15 CSV.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/UNSW_NB15_processed.csv"),
        help="Path for the processed CSV output.",
    )
    parser.add_argument(
        "--preprocessor",
        type=Path,
        default=Path("models/preprocessor.joblib"),
        help="Path to save/load the fitted preprocessor.",
    )
    parser.add_argument(
        "--mode",
        choices=["fit", "transform"],
        default="fit",
        help="fit: fit on input and save transformer; transform: reuse existing transformer to process input.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.mode == "fit":
        saved_path = preprocess_fit(args.input, args.output, args.preprocessor)
    else:
        saved_path = preprocess_transform(args.input, args.output, args.preprocessor)
    print(f"Processed data saved to {saved_path}")


if __name__ == "__main__":
    main()
