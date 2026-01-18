"""Signature-based intrusion detection rules.

Each rule returns a tuple (flag, reason).
Rules are lightweight and can operate on a pandas.Series row from the processed dataset.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

import pandas as pd

# Tunable thresholds tailored to UNSW-NB15 fields
SENSITIVE_SERVICES = {"ssh", "telnet", "ftp", "smtp", "snmp", "rdp"}
SENSITIVE_SERVICE_MIN_BYTES = 1_000  # bytes exchanged to treat as notable volume on sensitive services
ICMP_FLOOD_MIN_PKTS = 3              # total packets in a single ICMP flow
HIGH_CONN_COUNT_THRESHOLD = 40       # ct_* long-term counts seen in UNSW-NB15


def _safe_get(row: pd.Series, keys: Iterable[str], default=None):
    for key in keys:
        if key in row and pd.notna(row[key]):
            return row[key]
    return default


def detect_sensitive_service(row: pd.Series) -> Tuple[bool, str]:
    """Flag non-trivial traffic on sensitive services (UNSW uses service names, not ports)."""
    service = str(_safe_get(row, ["service"], default="") or "").lower()
    if service not in SENSITIVE_SERVICES:
        return False, ""

    sbytes = _safe_get(row, ["sbytes", "src_bytes"], default=0) or 0
    dbytes = _safe_get(row, ["dbytes", "dst_bytes"], default=0) or 0
    total_bytes = sbytes + dbytes
    if total_bytes >= SENSITIVE_SERVICE_MIN_BYTES:
        return True, f"Sensitive service {service} with {total_bytes} bytes exchanged"
    return False, ""


def detect_icmp_flood(row: pd.Series) -> Tuple[bool, str]:
    """Flag potential ICMP flood: ICMP protocol with unusually many packets."""
    proto = str(_safe_get(row, ["proto"], default="")).lower()
    if proto != "icmp":
        return False, ""

    spkts = _safe_get(row, ["spkts", "src_pkts"], default=0) or 0
    dpkts = _safe_get(row, ["dpkts", "dst_pkts"], default=0) or 0
    total_pkts = spkts + dpkts
    if total_pkts >= ICMP_FLOOD_MIN_PKTS:
        return True, f"ICMP flood suspicion: {total_pkts} packets in single flow"
    return False, ""


def detect_high_connection_rate(row: pd.Series) -> Tuple[bool, str]:
    """Flag abnormally high recent connection counts per source or destination."""
    counts = {
        "ct_src_ltm": _safe_get(row, ["ct_src_ltm"], default=0) or 0,
        "ct_dst_ltm": _safe_get(row, ["ct_dst_ltm"], default=0) or 0,
        "ct_src_dport_ltm": _safe_get(row, ["ct_src_dport_ltm"], default=0) or 0,
        "ct_dst_sport_ltm": _safe_get(row, ["ct_dst_sport_ltm"], default=0) or 0,
    }
    hit_fields: List[str] = [name for name, val in counts.items() if val >= HIGH_CONN_COUNT_THRESHOLD]
    if hit_fields:
        details = ", ".join(f"{field}={int(counts[field])}" for field in hit_fields)
        return True, f"Abnormal connection rate ({details})"
    return False, ""


def evaluate_signatures(row: pd.Series) -> Tuple[bool, List[str]]:
    """Evaluate all signature rules for a single record.

    Returns
    -------
    flag : bool
        True if any rule triggers.
    reasons : list of str
        Human-readable reasons for triggered rules.
    """
    checks = [detect_sensitive_service, detect_icmp_flood, detect_high_connection_rate]
    reasons: List[str] = []
    for check in checks:
        flag, reason = check(row)
        if flag and reason:
            reasons.append(reason)
    return bool(reasons), reasons


def evaluate_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply signature rules to every row and return a DataFrame with flags and reasons."""
    results: List[Dict[str, object]] = []
    for _, row in df.iterrows():
        flag, reasons = evaluate_signatures(row)
        results.append({"signature_flag": flag, "signature_reasons": "; ".join(reasons)})
    return pd.DataFrame(results)
