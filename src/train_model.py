"""Train a RandomForest classifier for UNSW-NB15 and persist the model."""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

DEFAULT_PROCESSED = Path("data/processed/UNSW_NB15_processed.csv")
DEFAULT_MODEL = Path("models/rf_classifier.joblib")
DEFAULT_FEATURE_NAMES = Path("models/feature_names.joblib")


def load_data(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError("Processed dataset must include a 'label' column.")
    y = df["label"].astype(int)
    X = df.drop(columns=["label"])
    return X, y


def train_model(X: pd.DataFrame, y: pd.Series, n_estimators: int = 300, random_state: int = 42) -> RandomForestClassifier:
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X, y)
    return clf


def evaluate(clf: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series) -> None:
    preds = clf.predict(X_test)
    cm = confusion_matrix(y_test, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, preds, average=None, labels=[0, 1])
    print("Confusion matrix (rows=true, cols=pred):")
    print(cm)
    print("\nPer-class metrics (label order: 0=normal, 1=attack):")
    print(f"Precision: {precision}")
    print(f"Recall:    {recall}  <-- focus on recall[1] for attacks")
    print(f"F1-score:  {f1}")
    print("\nClassification report:")
    print(classification_report(y_test, preds, digits=4))


def main() -> None:
    parser = argparse.ArgumentParser(description="Train RandomForest on UNSW-NB15 processed data.")
    parser.add_argument("--data", type=Path, default=DEFAULT_PROCESSED, help="Path to processed CSV.")
    parser.add_argument("--output", type=Path, default=DEFAULT_MODEL, help="Where to save the trained model.")
    parser.add_argument(
        "--feature-names-output",
        type=Path,
        default=DEFAULT_FEATURE_NAMES,
        help="Where to save the feature name list.",
    )
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split fraction.")
    parser.add_argument("--n-estimators", type=int, default=300, help="Number of trees (>=200).")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for reproducibility.")
    args = parser.parse_args()

    X, y = load_data(args.data)
    feature_names = X.columns.tolist()
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=y,
    )

    clf = train_model(X_train, y_train, n_estimators=args.n_estimators, random_state=args.random_state)
    evaluate(clf, X_test, y_test)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.feature_names_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(feature_names, args.feature_names_output)
    joblib.dump(clf, args.output)
    print(f"Model saved to {args.output}")
    print(f"Feature names saved to {args.feature_names_output}")


if __name__ == "__main__":
    main()
