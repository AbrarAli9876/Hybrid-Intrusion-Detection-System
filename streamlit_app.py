"""
Streamlit SOC-style dashboard for the hybrid IDS alerts.
"""
from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="Hybrid Intrusion Detection – Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DARK_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root {
    --bg: #0b0f14;
    --panel: #0f172a;
    --card: #0c111b;
    --stroke: rgba(255,255,255,0.06);
    --hi: #ef4444;
    --med: #f59e0b;
    --norm: #10b981;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --shadow: 0 22px 48px rgba(0,0,0,0.46);
}
html, body, [data-testid="stAppViewContainer"] {
    background: radial-gradient(circle at 20% 20%, rgba(239,68,68,0.08), transparent 28%),
                radial-gradient(circle at 82% 0%, rgba(88,28,135,0.18), transparent 38%),
                var(--bg);
    color: var(--text);
    font-family: "Space Grotesk", "Segoe UI", sans-serif;
}
[data-testid="stHeader"] {background: rgba(0,0,0,0);}
.block-container {padding-top: 1rem;}
h1, h2, h3, h4, h5, h6 {color: var(--text);} 

.header-wrap {display: flex; flex-direction: column; align-items: center; gap: 6px; margin-bottom: 14px; text-align: center;}
.eyebrow {color: var(--muted); font-size: 12px; letter-spacing: 1px; text-transform: uppercase;}
.title {font-size: 34px; font-weight: 800; letter-spacing: 0.2px;}
.subtitle {color: var(--muted); margin-top: 2px; font-size: 16px;}

.upload-card {background: linear-gradient(135deg, #0f172a, #0b1220); border: 1px solid var(--stroke); border-radius: 16px; padding: 18px 20px; box-shadow: var(--shadow); margin-bottom: 12px;}
.upload-title {font-weight: 600; font-size: 15px;}
.upload-sub {color: var(--muted); font-size: 13px; margin-top: 4px;}
[data-testid="stFileUploader"] {background: rgba(255,255,255,0.02); border: 1px dashed var(--stroke); border-radius: 12px; padding: 10px 12px;}
[data-testid="stFileUploader"] section {color: var(--text);} 
[data-testid="stFileUploader"] section div {color: var(--muted);} 

.metric-card {background: linear-gradient(135deg, #0d1625, #0b111d); border: 1px solid var(--stroke); border-radius: 14px; padding: 16px; box-shadow: var(--shadow); position: relative; overflow: hidden;}
.metric-card:after {content:""; position:absolute; inset: -10% -40% auto auto; height: 90px; width: 140px; background: radial-gradient(circle, rgba(255,255,255,0.08), transparent 50%); opacity: 0.6;}
.metric-card.metric-hi {border-color: rgba(239,68,68,0.5); box-shadow: 0 0 28px rgba(239,68,68,0.28);}
.metric-card.metric-med {border-color: rgba(245,158,11,0.35); box-shadow: 0 0 24px rgba(245,158,11,0.22);}
.metric-card.metric-norm {border-color: rgba(16,185,129,0.35); box-shadow: 0 0 20px rgba(16,185,129,0.18);}
.metric-value {font-size: 34px; font-weight: 700; margin: 2px 0 0 0;}
.metric-label {color: var(--muted); font-size: 13px; margin: 0; letter-spacing: 0.3px;}

.panel-card {background: linear-gradient(135deg, #0f172a, #0c111b); border: 1px solid var(--stroke); border-radius: 16px; padding: 14px 16px 8px; box-shadow: var(--shadow);}
.card-title {color: var(--muted); font-size: 13px; letter-spacing: 0.4px; text-transform: uppercase; margin-bottom: 8px;}
[data-testid="stMetricDelta"] {color: var(--muted);} 
[data-testid="stPlotlyChart"] {background: linear-gradient(135deg, #0f172a, #0c111b); border: 1px solid var(--stroke); border-radius: 16px; padding: 12px 12px 6px; box-shadow: var(--shadow);} 
[data-testid="stPlotlyChart"] .plot-container {background: transparent !important;}
[data-testid="stPlotlyChart"] .main-svg {border-radius: 12px;}

.stRadio [role="radiogroup"] {display: flex; gap: 10px; background: rgba(255,255,255,0.02); padding: 6px; border-radius: 999px; border: 1px solid var(--stroke);}
.stRadio [role="radiogroup"] label {flex:1; border-radius: 999px; padding: 8px 14px; border: 1px solid transparent; color: var(--text); transition: all 0.2s ease;}
.stRadio [role="radiogroup"] label:hover {border-color: var(--stroke); background: rgba(255,255,255,0.04);}
.stRadio [role="radiogroup"] label input:checked + div {background: linear-gradient(90deg, #ef4444, #991b1b); color: #fff; padding: 7px 12px; border-radius: 999px; border: 1px solid rgba(239,68,68,0.5); box-shadow: 0 0 18px rgba(239,68,68,0.35);} 

.alert-card {position: relative; background: linear-gradient(135deg, rgba(15,23,42,0.92), rgba(12,17,27,0.9)); border: 1px solid var(--stroke); border-radius: 18px; padding: 16px 18px; margin-bottom: 12px; box-shadow: var(--shadow); overflow: hidden;}
.alert-card.alert-high {border-color: rgba(239,68,68,0.45); box-shadow: 0 0 28px rgba(239,68,68,0.28);} 
.alert-card.alert-med {border-color: rgba(245,158,11,0.32); box-shadow: 0 0 24px rgba(245,158,11,0.22);} 
.alert-card.alert-high:before, .alert-card.alert-med:before, .alert-card.alert-norm:before {content:""; position:absolute; left:0; top:0; bottom:0; width: 5px;} 
.alert-card.alert-high:before {background: linear-gradient(180deg, rgba(239,68,68,0.9), rgba(239,68,68,0.35));}
.alert-card.alert-med:before {background: linear-gradient(180deg, rgba(245,158,11,0.85), rgba(245,158,11,0.28));}
.alert-card.alert-norm:before {background: linear-gradient(180deg, rgba(16,185,129,0.8), rgba(16,185,129,0.24));}
.alert-header {display: flex; justify-content: space-between; align-items: baseline; gap: 12px;}
.badge {padding: 6px 10px; border-radius: 10px; font-size: 12px; font-weight: 700; letter-spacing: 0.4px;}
.badge-high {background: rgba(239,68,68,0.16); color: #fecdd3; border: 1px solid rgba(239,68,68,0.35);} 
.badge-medium {background: rgba(245,158,11,0.16); color: #fcd34d; border: 1px solid rgba(245,158,11,0.35);} 
.badge-normal {background: rgba(16,185,129,0.16); color: #a7f3d0; border: 1px solid rgba(16,185,129,0.35);} 
.source-chip {padding: 4px 10px; border-radius: 10px; background: rgba(56,189,248,0.12); color: #e0f2fe; border: 1px solid rgba(56,189,248,0.3); font-size: 12px;}
.conf-bar {height: 7px; width: 100%; background: rgba(255,255,255,0.08); border-radius: 999px; overflow: hidden; margin-top: 8px;}
.conf-bar.conf-high > div {height: 100%; border-radius: 999px; background: linear-gradient(90deg, #ef4444, #b91c1c);} 
.conf-bar.conf-med > div {height: 100%; border-radius: 999px; background: linear-gradient(90deg, #f59e0b, #d97706);} 
.conf-bar.conf-norm > div {height: 100%; border-radius: 999px; background: linear-gradient(90deg, #10b981, #047857);} 
.evidence {color: #e5e7eb; margin: 10px 0 0 0; padding-left: 18px;}
.timestamp {color: var(--muted); font-size: 12px; margin-top: 8px; text-align: right;}
.section-title {font-size: 16px; font-weight: 700; margin: 12px 0 8px; letter-spacing: 0.3px;}
.info-muted {color: var(--muted); font-size: 12px;}
.chart-hero {max-width: 1180px; margin: 6px auto 20px auto; background: linear-gradient(145deg, rgba(15,23,42,0.95), rgba(12,17,27,0.9)); border: 1px solid var(--stroke); border-radius: 18px; padding: 22px 24px 18px; box-shadow: var(--shadow);} 
.chart-hero .chart-title {text-align: center; font-size: 22px; font-weight: 800; letter-spacing: 0.3px; margin-bottom: 4px;}
.chart-hero .chart-subtitle {text-align: center; color: var(--muted); font-size: 13px; letter-spacing: 0.2px; margin-bottom: 12px;}
.about-card {display:flex; gap:16px; align-items:center; background: linear-gradient(135deg, #0f172a, #0c111b); border: 1px solid var(--stroke); border-radius: 18px; padding: 14px 16px; box-shadow: var(--shadow); margin-bottom: 14px;}
.about-avatar {flex:0 0 120px; height:120px; border-radius:50%; display:flex; align-items:center; justify-content:center; background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.12), transparent 55%), linear-gradient(145deg, #1f2937, #0b0f14); border: 2px solid rgba(255,255,255,0.08); overflow:hidden;}
.about-img {width:120px; height:120px; object-fit:cover; border-radius:50%; display:block;}
.about-body {display:flex; flex-direction:column; gap:4px; color: var(--text);}
.about-name {font-size:24px; font-weight:800; letter-spacing:0.3px;}
.about-role {font-size:15px; color: var(--muted); font-weight:600; margin-bottom:6px;}
.about-row {font-size:14px; color: var(--text); display:flex; align-items:center; gap:8px;}
.about-links {display:flex; gap:14px; font-size:14px; color: var(--text); margin-top:6px;}
.about-links a {color: var(--text); text-decoration:none; border-bottom:1px solid transparent;}
.about-links a:hover {border-bottom-color: var(--text);}
.photo-toggle {display:none;}
.photo-modal {display:none; position:fixed; inset:0; background:rgba(0,0,0,0.75); align-items:center; justify-content:center; z-index:9999; padding:20px;}
.photo-toggle:checked ~ .photo-modal {display:flex;}
.photo-content {background:#0b0f14; border:1px solid var(--stroke); border-radius:16px; padding:12px; box-shadow:0 18px 42px rgba(0,0,0,0.5); max-width:90vw; max-height:90vh; display:flex; align-items:center; justify-content:center;}
.photo-full {max-width:86vw; max-height:86vh; border-radius:12px; object-fit:contain;}
.photo-backdrop {position:absolute; inset:0;}
.about-avatar {cursor:zoom-in;}
</style>
"""

st.markdown(DARK_CSS, unsafe_allow_html=True)

REQUIRED_COLUMNS = {"severity", "signature_flag", "ml_attack", "reasons"}
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
PHOTO_PATH = ASSETS_DIR / "developer.jpg"


def _as_bool(value: object) -> bool:
    """Return truthiness for diverse CSV encodings."""
    if isinstance(value, bool):
        return value
    if pd.isna(value):
        return False
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "y", "t"}


def _load_photo_data_url(path: Path) -> str:
    try:
        data = path.read_bytes()
        encoded = base64.b64encode(data).decode("ascii")
        suffix = path.suffix.lower()
        if suffix in {".jpg", ".jpeg"}:
            mime = "image/jpeg"
        elif suffix == ".png":
            mime = "image/png"
        elif suffix == ".svg":
            mime = "image/svg+xml"
        else:
            mime = "application/octet-stream"
        return f"data:{mime};base64,{encoded}"
    except Exception:
        return ""


def prepare_alerts(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()
    frame.columns = [c.strip() for c in frame.columns]
    frame["severity"] = frame["severity"].astype(str).str.upper().str.strip()
    frame["reasons"] = frame["reasons"].fillna("No evidence provided")
    frame["signature_flag"] = frame["signature_flag"].apply(_as_bool)
    frame["ml_attack"] = frame["ml_attack"].apply(_as_bool)

    def detection_source(row: pd.Series) -> str:
        sig = bool(row["signature_flag"])
        ml = bool(row["ml_attack"])
        if sig and ml:
            return "Hybrid"
        if sig:
            return "Signature"
        if ml:
            return "ML"
        return "Normal"

    frame["source"] = frame.apply(detection_source, axis=1)
    confidence_map = {"Signature": 100, "ML": 90, "Hybrid": 95, "Normal": 0}
    frame["confidence"] = frame["source"].map(confidence_map).fillna(0)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame["timestamp_display"] = frame["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    frame["timestamp_display"] = frame["timestamp_display"].fillna("Unknown time")
    return frame


def render_metrics(df: pd.DataFrame) -> None:
    total_alerts = (df["severity"] != "NONE").sum()
    high_alerts = (df["severity"] == "HIGH").sum()
    med_alerts = (df["severity"] == "MEDIUM").sum()
    normal_alerts = (df["severity"] == "NONE").sum()

    c1, c2, c3, c4 = st.columns(4)
    for col, label, value, css_class in (
        (c1, "Total Alerts", total_alerts, ""),
        (c2, "HIGH Alerts", high_alerts, "metric-hi"),
        (c3, "MEDIUM Alerts", med_alerts, "metric-med"),
        (c4, "Normal Alerts", normal_alerts, "metric-norm"),
    ):
        with col:
            st.markdown(
                f"<div class='metric-card {css_class}'><p class='metric-label'>{label}</p>"
                f"<p class='metric-value'>{value}</p></div>",
                unsafe_allow_html=True,
            )


def render_charts(df: pd.DataFrame) -> None:
    severity_order = ["HIGH", "MEDIUM", "NONE"]
    severity_df = (
        df.assign(severity=pd.Categorical(df["severity"], categories=severity_order, ordered=True))
        .value_counts("severity")
        .reset_index(name="count")
        .sort_values("severity")
    )
    total = severity_df["count"].sum()
    severity_df["pct"] = (severity_df["count"] / total * 100).round(1)
    chart_container = st.container()
    with chart_container:
        st.markdown(
            """
            <div class='chart-hero' style='text-align:center;'>
                <div class='chart-title'>Severity Distribution of Detected Alerts</div>
                <div class='chart-subtitle'>Overall security posture overview</div>
            """,
            unsafe_allow_html=True,
        )

        fig = px.pie(
            severity_df,
            names="severity",
            values="count",
            color="severity",
            category_orders={"severity": severity_order},
            color_discrete_map={
                "HIGH": "#ef4444",
                "MEDIUM": "#f59e0b",
                "NONE": "#10b981",
            },
            hole=0.55,
        )
        fig.update_traces(
            textinfo="percent+label",
            textposition="inside",
            textfont=dict(size=20, color="#0b0f14", family="Space Grotesk, sans-serif"),
            hovertemplate="%{label}: %{value} alerts (%{percent})",
            sort=False,
            direction="clockwise",
            marker=dict(line=dict(color="#0b0f14", width=3)),
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e5e7eb",
            height=900,
            width=900,
            margin=dict(t=0, b=0, l=0, r=0),
            legend=dict(
                bgcolor="rgba(0,0,0,0)",
                orientation="h",
                y=-0.2,
                x=0.5,
                xanchor="center",
                font=dict(size=15),
                title=None,
            ),
            uniformtext_minsize=12,
            uniformtext_mode="hide",
        )

        st.plotly_chart(fig, use_container_width=True, theme=None, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)


def render_top_ips(df: pd.DataFrame) -> None:
    st.markdown("<div class='section-title'>Top Attacking IP Addresses</div>", unsafe_allow_html=True)
    if "src_ip" not in df.columns:
        st.info("Source IP not available in alert data.")
        return

    ip_counts = df[df["severity"] != "NONE"].value_counts("src_ip").reset_index(name="count")
    if ip_counts.empty:
        st.info("No attacker IPs found in the provided alerts.")
        return

    top_ips = ip_counts.head(5)
    fig = px.bar(
        top_ips,
        x="src_ip",
        y="count",
        color="count",
        color_continuous_scale=["#0ea5e9", "#ef4444"],
    )
    fig.update_layout(
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        font_color="#e5e7eb",
        margin=dict(t=10, b=20, l=0, r=0),
        coloraxis_showscale=False,
    )
    fig.update_xaxes(showgrid=False, title="Source IP")
    fig.update_yaxes(showgrid=True, gridcolor="rgba(255,255,255,0.08)", title="Count")
    st.plotly_chart(fig, use_container_width=True, theme=None)


def render_alert_feed(df: pd.DataFrame) -> None:
    if df.empty:
        st.info("No alerts available from the uploaded file.")
        return

    st.markdown("<div class='section-title'>Alert Details</div>", unsafe_allow_html=True)

    filtered = df[df["severity"].isin(["HIGH", "MEDIUM"])]
    selected = (
        filtered.assign(_sev_rank=filtered["severity"].map({"HIGH": 0, "MEDIUM": 1}))
        .sort_values(by=["_sev_rank", "timestamp"], ascending=[True, False])
        .head(30)
        .drop(columns="_sev_rank", errors="ignore")
    )

    if selected.empty:
        st.info("No HIGH or MEDIUM alerts to display.")
        return

    for _, row in selected.iterrows():
        severity = row.get("severity", "NONE")
        severity_label = severity if severity != "NONE" else "NORMAL"
        badge_class = {"HIGH": "badge-high", "MEDIUM": "badge-medium"}.get(severity, "badge-normal")
        card_class = {"HIGH": "alert-high", "MEDIUM": "alert-med"}.get(severity, "alert-norm")
        conf_class = {"HIGH": "conf-high", "MEDIUM": "conf-med"}.get(severity, "conf-norm")
        conf = int(row.get("confidence", 0))
        evidence_points = [p.strip() for p in str(row.get("reasons", "")).split(";") if p.strip()]
        evidence_points = evidence_points or ["No evidence provided"]
        source = row.get("source", "Unknown")
        attack_category = row.get("attack_category", "Unknown")
        proto = str(row.get("protocol", "")).upper() or "N/A"
        service = str(row.get("service", "")).lower() or "n/a"
        duration = row.get("duration", "")
        try:
            duration_text = f"{float(duration):.2f}s"
        except (TypeError, ValueError):
            duration_text = str(duration) or "n/a"

        st.markdown(
            f"""
            <div class="alert-card {card_class}">
                <div class="alert-header">
                    <div>
                        <div class="eyebrow" style="letter-spacing:0.6px; color: var(--muted);">🚨 INTRUSION ALERT</div>
                        <div style="font-size:20px; font-weight:700; margin-top:2px;">{severity_label} Threat</div>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="badge {badge_class}">{severity_label}</span>
                        <span class="source-chip">{source} detection</span>
                    </div>
                </div>
                <div style="margin-top:10px; display:flex; flex-wrap:wrap; gap:12px; color: var(--muted); font-size:12px;">
                    <span><strong style="color:#e5e7eb;">Category:</strong> {attack_category}</span>
                    <span><strong style="color:#e5e7eb;">Protocol:</strong> {proto}</span>
                    <span><strong style="color:#e5e7eb;">Service:</strong> {service}</span>
                    <span><strong style="color:#e5e7eb;">Duration:</strong> {duration_text}</span>
                </div>
                <div style="margin-top:10px; display:flex; justify-content:space-between; color: var(--muted); font-size:12px;">
                    <span>Detection Source</span>
                    <span style="color: #e5e7eb;">{source}</span>
                </div>
                <div style="margin-top:10px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; font-size:12px; color: var(--muted);">
                        <span>Confidence</span>
                        <span>{conf}%</span>
                    </div>
                    <div class="conf-bar {conf_class}"><div style="width:{conf}%;"></div></div>
                </div>
                <ul class="evidence">
                    {''.join(f'<li>{point}</li>' for point in evidence_points)}
                </ul>
                <div class="timestamp">{row.get('timestamp_display', 'Unknown time')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def filter_alerts(df: pd.DataFrame, severity_filter: str, search: str) -> pd.DataFrame:
    filtered = df.copy()
    if severity_filter == "HIGH":
        filtered = filtered[filtered["severity"] == "HIGH"]
    elif severity_filter == "MEDIUM":
        filtered = filtered[filtered["severity"] == "MEDIUM"]

    if search:
        search_lower = search.lower()
        possible_fields: Iterable[str] = ["reasons"] + [c for c in df.columns if "ip" in c.lower()]
        mask = pd.Series(False, index=filtered.index)
        for col in possible_fields:
            if col in filtered.columns:
                mask = mask | filtered[col].astype(str).str.lower().str.contains(search_lower, na=False)
        filtered = filtered[mask]
    return filtered


st.markdown(
    """
    <div class="header-wrap">
        <div>
            <div class="title">SOC Dashboard</div>
            <div class="subtitle">Hybrid Intrusion Detection – Security Monitor</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# About Me section
photo_src = _load_photo_data_url(PHOTO_PATH)
avatar_img = f"<img class='about-img' src='{photo_src}' alt='K.S. Abrar Ali Ahmed' />" if photo_src else "<div class='about-avatar'>AA</div>"
full_img = f"<img class='photo-full' src='{photo_src}' alt='K.S. Abrar Ali Ahmed' />" if photo_src else ""
about_html = f"""
<div class="about-card">
    <input type="checkbox" id="photo-zoom" class="photo-toggle" />
    <label for="photo-zoom" class="about-avatar">{avatar_img}</label>
    <div class="photo-modal">
        <label for="photo-zoom" class="photo-backdrop"></label>
        <label for="photo-zoom" class="photo-content">{full_img}</label>
    </div>
    <div class="about-body">
        <div class="about-name">K.S. Abrar Ali Ahmed</div>
        <div class="about-role">Developer &amp; Student</div>
        <div class="about-row">📧 ksaabrarahmed2021@gmail.com</div>
        <div class="about-row">🏫 K S School of Engineering and Management</div>
        <div class="about-links">
            <a href="https://www.linkedin.com/in/abrar-ali-ahmed/" target="_blank" rel="noopener">LinkedIn</a>
            <a href="https://github.com/AbrarAli9876/" target="_blank" rel="noopener">GitHub</a>
        </div>
    </div>
</div>
"""
st.markdown(about_html, unsafe_allow_html=True)

with st.container():
    st.markdown("<div class='upload-card'>", unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Upload alerts.csv",
        type=["csv"],
        accept_multiple_files=False,
        label_visibility="collapsed",
    )
    st.markdown("</div>", unsafe_allow_html=True)

if not uploaded:
    st.stop()

if "alerts" not in uploaded.name.lower():
    st.warning("This uploader is intended for the hybrid IDS alerts.csv output. Please confirm the file is correct.")

raw_df = pd.read_csv(uploaded)
missing = REQUIRED_COLUMNS - set(raw_df.columns)
if missing:
    st.error(f"The file is missing required columns: {', '.join(sorted(missing))}")
    st.stop()

if "timestamp" not in raw_df.columns:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_df["timestamp"] = now_str

alerts_df = prepare_alerts(raw_df)

# Debug schema check — remove after verification
st.markdown("<div class='info-muted'>Debug: columns loaded</div>", unsafe_allow_html=True)
st.code(list(alerts_df.columns))

st.markdown("<div class='section-title'>Situational Overview</div>", unsafe_allow_html=True)
render_metrics(alerts_df)

render_charts(alerts_df)

render_alert_feed(alerts_df)
