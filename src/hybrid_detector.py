"""Hybrid detection pipeline combining signatures, ML classifier, and anomaly detector."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
from joblib import load

from src.signatures import evaluate_signatures


DEFAULT_RAW = Path("data/raw/UNSW_NB15_training-set.csv")
DEFAULT_PROCESSED = Path("data/processed/UNSW_NB15_processed.csv")
DEFAULT_CLF = Path("models/rf_classifier.joblib")
DEFAULT_FEATURE_NAMES = Path("models/feature_names.joblib")
DEFAULT_ANOMALY = Path("models/anomaly_iforest.joblib")
DEFAULT_OUTPUT = Path("outputs/alerts.csv")


def _load_optional_model(path: Path):
    if path.exists():
        return load(path)
    return None


def _load_feature_names(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Training feature list not found at {path}")
    loaded = list(load(path))
    if not loaded:
        raise ValueError("Loaded feature names are empty; cannot align features for inference")
    return loaded


def _align_features(X: pd.DataFrame, feature_names: list[str]) -> pd.DataFrame:
    aligned = X.copy()
    missing = [col for col in feature_names if col not in aligned.columns]
    for col in missing:
        aligned[col] = 0
    extra = [col for col in aligned.columns if col not in feature_names]
    if extra:
        aligned = aligned.drop(columns=extra)
    return aligned[feature_names]


def _coerce_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def derive_attack_category(
    severity: str,
    proto: str,
    service: str,
    signature_flag: bool,
    ml_attack: bool,
    anomaly_flag: bool,
    raw_row: pd.Series,
) -> str:
    """Heuristic attack category for analyst context."""
    sev = (severity or "NONE").upper()
    proto_l = (proto or "").lower()
    service_l = (service or "").lower()

    # Basic scan heuristics using connection counts if present
    ct_dst = _coerce_float(raw_row.get("ct_dst_ltm"), 0)
    ct_dst_sport = _coerce_float(raw_row.get("ct_dst_sport_ltm"), 0)

    if sev == "NONE":
        return "Normal"
    if proto_l == "icmp" and sev == "HIGH":
        return "DoS / Flood"
    if service_l in {"ftp", "ssh"} and sev == "HIGH":
        return "Brute Force"
    if (ct_dst >= 20 or ct_dst_sport >= 20) and sev != "NONE":
        return "Reconnaissance / Port Scan"
    if service_l == "http" and ml_attack and not signature_flag:
        return "Web Attack"
    if ml_attack and not signature_flag:
        return "Unknown / Suspicious"
    if anomaly_flag and not (signature_flag or ml_attack):
        return "Anomalous / Suspicious"
    return "Unknown / Suspicious"


def hybrid_decision(signature_flag: bool, ml_attack: bool, anomaly_flag: bool, reasons: List[str]) -> Tuple[bool, str, List[str]]:
    """Return (alert, severity, reasons) based on signals."""
    if signature_flag:
        return True, "HIGH", reasons
    if ml_attack and anomaly_flag:
        reasons.append("ML attack + anomaly agreement")
        return True, "HIGH", reasons
    if ml_attack:
        reasons.append("ML classifier predicted attack")
        return True, "MEDIUM", reasons
    if anomaly_flag:
        reasons.append("Anomaly detector flagged outlier")
        return True, "LOW", reasons
    return False, "NONE", reasons


def run_hybrid(
    raw_csv: Path = DEFAULT_RAW,
    processed_csv: Path = DEFAULT_PROCESSED,
    clf_path: Path = DEFAULT_CLF,
    feature_names_path: Path = DEFAULT_FEATURE_NAMES,
    anomaly_path: Path = DEFAULT_ANOMALY,
    output_csv: Path = DEFAULT_OUTPUT,
) -> Path:
    raw_df = pd.read_csv(raw_csv)
    processed_df = pd.read_csv(processed_csv)

    if len(raw_df) != len(processed_df):
        raise ValueError(f"Row count mismatch: raw={len(raw_df)} processed={len(processed_df)}")

    # Prepare ML features
    X = processed_df.drop(columns=["label"], errors="ignore")
    clf = _load_optional_model(clf_path)
    anomaly = _load_optional_model(anomaly_path)

    ml_preds: List[Optional[int]]
    if clf is not None:
        feature_names = _load_feature_names(feature_names_path)
        X_ml = _align_features(X, feature_names)
        ml_preds = clf.predict(X_ml)
    else:
        ml_preds = [None] * len(processed_df)

    anomaly_preds: List[Optional[int]]
    if anomaly is not None:
        anomaly_preds = anomaly.predict(X)  # -1 = anomaly, 1 = normal for IsolationForest
    else:
        anomaly_preds = [None] * len(processed_df)

    rows: List[dict] = []
    for idx, raw_row in raw_df.iterrows():
        sig_flag, sig_reasons = evaluate_signatures(raw_row)
        ml_attack = bool(ml_preds[idx]) if ml_preds[idx] is not None else False
        anomaly_flag = anomaly_preds[idx] == -1 if anomaly_preds[idx] is not None else False

        alert, severity, reasons = hybrid_decision(sig_flag, ml_attack, anomaly_flag, list(sig_reasons))
        proto = raw_row.get("proto", "")
        service = raw_row.get("service", "")
        duration = _coerce_float(raw_row.get("dur"), 0.0)
        attack_category = derive_attack_category(
            severity=severity,
            proto=proto,
            service=service,
            signature_flag=sig_flag,
            ml_attack=ml_attack,
            anomaly_flag=anomaly_flag,
            raw_row=raw_row,
        )
        rows.append(
            {
                "index": idx,
                "alert": alert,
                "severity": severity,
                "signature_flag": sig_flag,
                "ml_attack": ml_attack,
                "anomaly_flag": anomaly_flag,
                "reasons": "; ".join(reasons),
                "duration": duration,
                "protocol": str(proto).lower(),
                "service": str(service).lower(),
                "attack_category": attack_category,
            }
        )

    output_df = pd.DataFrame(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(output_csv, index=False)
    return output_csv


def summarize_alerts(alerts_csv: Path, head: int = 5) -> None:
    """Print severity counts and a small sample of alerts."""
    if not alerts_csv.exists():
        print(f"No alerts file found at {alerts_csv}")
        return
    df = pd.read_csv(alerts_csv)
    print("\nSeverity counts:")
    if "severity" in df.columns:
        print(df["severity"].value_counts())
    else:
        print("(missing 'severity' column)")

    print("\nSample alerts:")
    cols = [c for c in ["index", "severity", "alert", "signature_flag", "ml_attack", "anomaly_flag", "reasons"] if c in df.columns]
    print(df[cols].head(head))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run hybrid intrusion detection.")
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW, help="Path to raw CSV for signature evaluation.")
    parser.add_argument(
        "--processed",
        type=Path,
        default=DEFAULT_PROCESSED,
        help="Path to processed CSV for ML/anomaly inference.",
    )
    parser.add_argument("--clf", type=Path, default=DEFAULT_CLF, help="Path to classifier joblib.")
    parser.add_argument(
        "--feature-names",
        type=Path,
        default=DEFAULT_FEATURE_NAMES,
        help="Path to joblib containing training feature names.",
    )
    parser.add_argument("--anomaly", type=Path, default=DEFAULT_ANOMALY, help="Path to anomaly detector joblib.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Path to alerts CSV output.")
    parser.add_argument("--head", type=int, default=5, help="Number of sample alerts to display in summary.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    saved = run_hybrid(args.raw, args.processed, args.clf, args.feature_names, args.anomaly, args.output)
    print(f"Alerts saved to {saved}")
    summarize_alerts(saved, head=args.head)


if __name__ == "__main__":
    main()
