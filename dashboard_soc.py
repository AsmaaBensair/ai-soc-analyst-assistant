"""
dashboard_soc.py — SOC Assistant Enterprise Dashboard v3.0
Streamlit | Professional Dark Theme | SOC Analyst Grade

Features v3:
  - Multi-log correlation view
  - Threat Intel enrichment panel
  - SOAR playbook display
  - Supervised feedback loop (analyst TP/FP override)
  - MITRE ATT&CK heatmap
  - Campaign timeline
  - Risk score distribution
  - Hallucination analysis
  - Alert quality evaluation

Run: streamlit run dashboard_soc.py
"""

import json
import os
from datetime import datetime
from typing import Optional, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SOC AI Analyst - Enterprise v3",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# THEME & CSS - Professional Dark SOC Theme
# ─────────────────────────────────────────────
def load_css():
    st.markdown("""
    <style>
    /* Base - Professional Dark Theme */
    .stApp {
        background: #0a0c10;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        color: #c5d0de;
    }
    
    /* Headers */
    .stApp h1, .stApp h2, .stApp h3 {
        color: #ffffff;
        font-weight: 500;
        letter-spacing: -0.01em;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #0f1117;
        border-right: 1px solid #1e2433;
    }
    
    [data-testid="stSidebar"] .stMarkdown {
        color: #8a99b0;
    }
    
    /* Metrics Cards */
    [data-testid="stMetric"] {
        background: #13161d;
        border: 1px solid #1e2433;
        border-radius: 6px;
        padding: 1rem;
        transition: all 0.2s ease;
    }
    
    [data-testid="stMetric"]:hover {
        border-color: #2d3748;
        transform: translateY(-1px);
    }
    
    [data-testid="stMetric"] label {
        color: #6c7a91 !important;
        font-size: 0.7rem !important;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 600;
    }
    
    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 1.8rem !important;
        font-weight: 600;
    }
    
    /* Severity Badges */
    .badge-critical {
        background: #7f1d1d;
        color: #fca5a5;
        border: 1px solid #ef4444;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
        display: inline-block;
    }
    
    .badge-high {
        background: #7c2d12;
        color: #fdba74;
        border: 1px solid #f97316;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .badge-medium {
        background: #713f12;
        color: #fde68a;
        border: 1px solid #eab308;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .badge-low {
        background: #14532d;
        color: #86efac;
        border: 1px solid #22c55e;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .badge-clean {
        background: #1e3a5f;
        color: #93c5fd;
        border: 1px solid #3b82f6;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    /* Alert Cards */
    .alert-card {
        background: #13161d;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin: 0.5rem 0;
        border-left: 3px solid;
        border-top: 1px solid #1e2433;
        border-right: 1px solid #1e2433;
        border-bottom: 1px solid #1e2433;
    }
    
    .alert-card.critical { border-left-color: #ef4444; }
    .alert-card.high { border-left-color: #f97316; }
    .alert-card.medium { border-left-color: #eab308; }
    .alert-card.low { border-left-color: #22c55e; }
    
    /* Campaign Cards */
    .campaign-card {
        background: #0f1119;
        border: 1px solid #2d3748;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin: 0.5rem 0;
    }
    
    /* Threat Intel Badges */
    .ti-malicious {
        background: #5b1a1a;
        color: #fca5a5;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .ti-suspicious {
        background: #3d2608;
        color: #fdba74;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    .ti-clean {
        background: #0f2b0f;
        color: #86efac;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 600;
    }
    
    /* Section Separators */
    .sep {
        border-top: 1px solid #1e2433;
        margin: 1.5rem 0;
    }
    
    /* Tabs */
    [data-testid="stTabs"] button {
        color: #6c7a91 !important;
        font-size: 0.82rem;
        font-weight: 500;
    }
    
    [data-testid="stTabs"] button[aria-selected="true"] {
        color: #ffffff !important;
        border-bottom: 2px solid #3b82f6 !important;
    }
    
    /* DataFrames */
    [data-testid="stDataFrame"] {
        background: #13161d;
        border-radius: 6px;
        border: 1px solid #1e2433;
    }
    
    /* Progress Bar */
    .fp-bar-wrap {
        background: #1e2433;
        border-radius: 2px;
        height: 4px;
        width: 100%;
        margin-top: 4px;
    }
    
    .fp-bar {
        height: 4px;
        border-radius: 2px;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        color: #4a5a75;
        font-size: 0.7rem;
        padding: 1.5rem;
        margin-top: 2rem;
        border-top: 1px solid #1e2433;
    }
    
    /* Code Blocks */
    .code-block {
        background: #0c0f14;
        border: 1px solid #1a1f2e;
        border-radius: 4px;
        padding: 0.75rem 1rem;
        font-family: 'SF Mono', 'Monaco', 'Cascadia Code', monospace;
        font-size: 0.75rem;
        color: #a5d6ff;
        overflow-x: auto;
    }
    
    /* Buttons */
    [data-testid="stButton"] button {
        background: #1e2433;
        color: #c5d0de;
        border: 1px solid #2d3748;
        border-radius: 4px;
        transition: all 0.2s ease;
    }
    
    [data-testid="stButton"] button:hover {
        background: #2d3748;
        border-color: #3b82f6;
        color: #ffffff;
    }
    
    /* Select Boxes */
    [data-testid="stSelectbox"] div {
        background: #13161d;
        border-color: #1e2433;
    }
    
    /* Info/Warning/Error Messages */
    .stAlert {
        background: #13161d;
        border: 1px solid #1e2433;
        border-radius: 6px;
    }
    
    /* Expanders */
    [data-testid="stExpander"] details {
        background: #13161d;
        border: 1px solid #1e2433;
        border-radius: 6px;
    }
    
    [data-testid="stExpander"] summary {
        color: #c5d0de;
        font-weight: 500;
    }
    </style>
    """, unsafe_allow_html=True)

load_css()

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}
SEV_ICON = {"CRITICAL": "●", "HIGH": "●", "MEDIUM": "●", "LOW": "●", "": "○"}
PLOT_BG = "rgba(0,0,0,0)"
FONT_CLR = "#8a99b0"
GRID_CLR = "#1e2433"

MITRE_TACTICS_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact",
]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def badge(sev: str) -> str:
    cls = sev.lower() if sev.lower() in ("critical", "high", "medium", "low") else "clean"
    label = sev if sev else "CLEAN"
    return f'<span class="badge-{cls}">{label}</span>'


def ti_badge(rep: str) -> str:
    rep = (rep or "").upper()
    if rep == "MALICIOUS":
        return '<span class="ti-malicious">MALICIOUS</span>'
    elif rep == "SUSPICIOUS":
        return '<span class="ti-suspicious">SUSPICIOUS</span>'
    return '<span class="ti-clean">CLEAN</span>'


def layout_chart(fig, title="", height=300):
    fig.update_layout(
        paper_bgcolor=PLOT_BG,
        plot_bgcolor=PLOT_BG,
        font_color=FONT_CLR,
        font_family="-apple-system, BlinkMacSystemFont, sans-serif",
        margin=dict(t=40, b=20, l=10, r=10),
        height=height,
        title=title,
        title_font_color="#ffffff",
        title_font_size=13,
        title_font_weight=500,
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font_color=FONT_CLR,
            title_font_color=FONT_CLR
        ),
        hoverlabel=dict(
            bgcolor="#1e2433",
            font_color="#ffffff"
        )
    )
    fig.update_xaxes(
        gridcolor=GRID_CLR,
        linecolor=GRID_CLR,
        title_font_color=FONT_CLR,
        tickfont_color=FONT_CLR
    )
    fig.update_yaxes(
        gridcolor=GRID_CLR,
        linecolor=GRID_CLR,
        title_font_color=FONT_CLR,
        tickfont_color=FONT_CLR
    )
    return fig


def fp_bar(score: int) -> str:
    pct = min(100, max(0, score))
    color = "#ef4444" if pct < 30 else "#eab308" if pct < 60 else "#22c55e"
    return (f'<div class="fp-bar-wrap"><div class="fp-bar" '
            f'style="width:{pct}%;background:{color}"></div></div>')


# ─────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────

@st.cache_data(ttl=30)
def load_results(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


@st.cache_data(ttl=30)
def load_eval(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def normalize_results(raw_data: dict) -> pd.DataFrame:
    """Flatten pipeline results into a DataFrame."""
    rows = []
    for r in raw_data.get("results", []):
        alert = r.get("alert", {})
        corr = r.get("correlation", {})
        ti = r.get("threat_intel", {})
        soar = alert.get("soar_response", {})

        rows.append({
            "result_id": r.get("result_id"),
            "log_index": r.get("log_index"),
            "log_type": r.get("log_type", "unknown"),
            "source_ip": r.get("source_ip"),
            "timestamp": r.get("timestamp"),
            "pipeline_status": r.get("status", ""),
            # alert fields
            "is_alert": alert.get("is_alert", False),
            "alert_type": alert.get("alert_type", ""),
            "severity": alert.get("severity", ""),
            "fp_score": alert.get("false_positive_score", 50),
            "risk_score": alert.get("risk_score", 0),
            "confidence": alert.get("confidence", 0),
            "true_positive": alert.get("true_positive", False),
            "false_positive": alert.get("false_positive", False),
            "outcome": alert.get("outcome", ""),
            "summary": alert.get("summary", ""),
            "target_url": alert.get("target_url", ""),
            "user": alert.get("user", ""),
            "user_agent": alert.get("user_agent", ""),
            "status_code": alert.get("status_code", ""),
            "mitre_tactic": alert.get("mitre_tactic", ""),
            "mitre_tactic_id": alert.get("mitre_tactic_id", ""),
            "mitre_technique": alert.get("mitre_technique", ""),
            "mitre_t_id": alert.get("mitre_technique_id", ""),
            "escalate": alert.get("escalate_to_soc_level2", False),
            "esc_reason": alert.get("escalation_reason", ""),
            "hallucinated": alert.get("hallucination_detected", False),
            "h_flags": alert.get("hallucination_flags", []),
            "h_score": alert.get("hallucination_score", 0),
            "actions": alert.get("recommended_actions", []),
            "evidence": alert.get("attack_evidence", []),
            "fp_reason": alert.get("false_positive_reason", ""),
            # correlation
            "is_campaign": corr.get("is_campaign", False),
            "campaign_indicators": corr.get("campaign_indicators", []),
            "corr_risk": corr.get("correlation_risk_score", 0),
            "corr_summary": corr.get("correlation_summary", ""),
            # threat intel
            "ti_reputation": ti.get("reputation", ""),
            "ti_score": ti.get("threat_score", 0),
            "ti_tags": ti.get("tags", []),
            # soar
            "soar_playbook": soar.get("playbook_name", ""),
            "soar_escalate": soar.get("auto_escalate", False),
            "soar_ticket": soar.get("ticket", {}).get("ticket_id", ""),
            "soar_sla": soar.get("sla_response_minutes", 60),
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## SOC AI Analyst")
    st.markdown("**Enterprise Edition v3.0**")
    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    results_file = st.text_input("Results File", value="data/results_docker.json")
    eval_file = st.text_input("Evaluation Report", value="data/evaluation_report.json")

    if st.button("Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)
    st.markdown("### Filters")

    raw_data = load_results(results_file)
    eval_data = load_eval(eval_file)

    if not raw_data:
        st.error("No results file found. Run the pipeline first.")
        st.stop()

    df_full = normalize_results(raw_data)
    df_full["is_alert"] = df_full["is_alert"].fillna(False)

    # Severity filter
    all_sevs = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_filter = st.selectbox("Severity", all_sevs)

    # Alert type filter
    alert_types = ["ALL"] + sorted(df_full[df_full["is_alert"]]["alert_type"].dropna().unique().tolist())
    type_filter = st.selectbox("Attack Type", alert_types)

    # Outcome filter
    outcomes = ["ALL"] + sorted(df_full["outcome"].dropna().unique().tolist())
    outcome_filt = st.selectbox("Outcome", outcomes)

    # TI reputation filter
    ti_reps = ["ALL", "MALICIOUS", "SUSPICIOUS", "CLEAN"]
    ti_filter = st.selectbox("Threat Intel Reputation", ti_reps)

    # Escalated only
    esc_only = st.checkbox("Escalated Only")
    camp_only = st.checkbox("Campaigns Only")
    tp_only = st.checkbox("True Positives Only")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    # Pipeline stats
    meta = raw_data.get("metadata", {})
    st.markdown(f"**Mode:** `{meta.get('mode', 'N/A')}`")
    st.markdown(f"**Generated:** {meta.get('generated_at', '')[:19]}")
    stats = raw_data.get("statistics", {})
    dur = stats.get("duration_sec", 0)
    st.markdown(f"**Duration:** `{dur}s`")
    campaigns = raw_data.get("campaigns", [])
    st.markdown(f"**Campaigns:** `{len(campaigns)}`")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="color:#4a5a75;font-size:0.7rem">SOC AI Enterprise v3.0<br>'
        'Rules + LLM + Threat Intel + SOAR<br>'
        'Anti-hallucination · Feedback Loop</div>',
        unsafe_allow_html=True
    )

# ─────────────────────────────────────────────
# APPLY FILTERS
# ─────────────────────────────────────────────
df = df_full.copy()
if sev_filter != "ALL":
    df = df[df["severity"] == sev_filter]
if type_filter != "ALL":
    df = df[df["alert_type"] == type_filter]
if outcome_filt != "ALL":
    df = df[df["outcome"] == outcome_filt]
if ti_filter != "ALL":
    df = df[df["ti_reputation"] == ti_filter]
if esc_only:
    df = df[df["escalate"] == True]
if camp_only:
    df = df[df["is_campaign"] == True]
if tp_only:
    df = df[df["true_positive"] == True]

df_alerts = df[df["is_alert"] == True].copy()

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.markdown(
    '<h1 style="margin-bottom:0.25rem">SOC AI Analyst Dashboard</h1>'
    '<p style="color:#6c7a91;margin-bottom:1.5rem">Enterprise Threat Detection · Version 3.0 · '
    f'Last refresh: {datetime.now().strftime("%H:%M:%S")}</p>',
    unsafe_allow_html=True
)

# ─────────────────────────────────────────────
# KPI ROW
# ─────────────────────────────────────────────
alert_sum = raw_data.get("statistics", {}).get("alert_summary", {})
all_alerts = df_full[df_full["is_alert"]]
n_critical = len(df_full[df_full["severity"] == "CRITICAL"])
n_escalated = len(df_full[df_full["escalate"] == True])
n_campaigns = len(campaigns)
n_halluc = len(df_full[df_full["hallucinated"] == True])
n_ti_bad = len(df_full[df_full["ti_reputation"] == "MALICIOUS"])

k1, k2, k3, k4, k5, k6, k7 = st.columns(7)
k1.metric("Logs Analyzed", f"{len(df_full):,}")
k2.metric("Alerts", f"{alert_sum.get('alerts_generated', 0):,}")
k3.metric("Critical", f"{n_critical:,}")
k4.metric("Escalated L2", f"{n_escalated:,}")
k5.metric("Campaigns", f"{n_campaigns:,}")
k6.metric("Malicious IPs", f"{n_ti_bad:,}")
k7.metric("Hallucinations", f"{n_halluc:,}")

st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab_overview, tab_alerts, tab_campaigns, tab_mitre, tab_ti, tab_soar, tab_eval, tab_feedback = st.tabs([
    "Overview",
    "Alerts",
    "Campaigns",
    "MITRE ATT&CK",
    "Threat Intelligence",
    "SOAR",
    "Evaluation",
    "Feedback",
])

# ══════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ══════════════════════════════════════════════
with tab_overview:
    # Row 1: severity + attack type
    c1, c2, c3 = st.columns([1, 1, 1])

    with c1:
        st.markdown("#### Severity Distribution")
        sev_counts = df_full[df_full["is_alert"]]["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        if not sev_counts.empty:
            color_map = {k: v for k, v in SEV_COLOR.items()}
            fig = px.pie(sev_counts, values="Count", names="Severity",
                         color="Severity", color_discrete_map=color_map, hole=0.4)
            fig = layout_chart(fig, height=280)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts available")

    with c2:
        st.markdown("#### Attack Type Distribution")
        type_counts = df_full[df_full["is_alert"]]["alert_type"].value_counts().head(10).reset_index()
        type_counts.columns = ["Type", "Count"]
        if not type_counts.empty:
            fig2 = px.bar(type_counts, x="Count", y="Type", orientation="h",
                          color="Count", color_continuous_scale=["#1e3a5f", "#3b82f6", "#ef4444"])
            fig2 = layout_chart(fig2, height=280)
            fig2.update_coloraxes(showscale=False)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No alerts available")

    with c3:
        st.markdown("#### Outcome Distribution")
        outcome_counts = df_full[df_full["is_alert"]]["outcome"].value_counts().reset_index()
        outcome_counts.columns = ["Outcome", "Count"]
        if not outcome_counts.empty:
            ocmap = {"success": "#ef4444", "failure": "#f97316", "blocked": "#22c55e", "unknown": "#718096"}
            fig3 = px.pie(outcome_counts, values="Count", names="Outcome",
                          color="Outcome", color_discrete_map=ocmap, hole=0.4)
            fig3 = layout_chart(fig3, height=280)
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No data available")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    # Row 2: top IPs + risk score distribution
    c4, c5 = st.columns([1, 1])

    with c4:
        st.markdown("#### Top Source IP Addresses")
        ip_counts = df_full[df_full["is_alert"]]["source_ip"].value_counts().head(10).reset_index()
        ip_counts.columns = ["IP Address", "Alert Count"]
        if not ip_counts.empty:
            fig4 = px.bar(ip_counts, x="Alert Count", y="IP Address", orientation="h",
                          color="Alert Count", color_continuous_scale=["#1a3a2a", "#22c55e", "#ef4444"])
            fig4 = layout_chart(fig4, height=300)
            fig4.update_coloraxes(showscale=False)
            st.plotly_chart(fig4, use_container_width=True)
        else:
            st.info("No IP data available")

    with c5:
        st.markdown("#### Risk Score Distribution")
        risk_data = df_full[df_full["is_alert"] & df_full["risk_score"].notna()]["risk_score"]
        if not risk_data.empty:
            fig5 = px.histogram(risk_data, nbins=20,
                                color_discrete_sequence=["#3b82f6"],
                                labels={"value": "Risk Score", "count": "Frequency"})
            fig5.update_traces(marker_line_color="#1e3a5f", marker_line_width=1)
            fig5 = layout_chart(fig5, height=300)
            st.plotly_chart(fig5, use_container_width=True)
        else:
            st.info("No risk score data available")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    # Row 3: Log type breakdown + TP/FP ratio
    c6, c7 = st.columns([2, 1])

    with c6:
        st.markdown("#### Log Type Distribution")
        type_alert = df_full.groupby(["log_type", "is_alert"]).size().reset_index(name="count")
        type_alert["Status"] = type_alert["is_alert"].map({True: "Alert", False: "Clean"})
        fig6 = px.bar(type_alert, x="log_type", y="count", color="Status",
                      color_discrete_map={"Alert": "#ef4444", "Clean": "#22c55e"},
                      barmode="stack",
                      labels={"log_type": "Log Source", "count": "Count"})
        fig6 = layout_chart(fig6, height=280)
        st.plotly_chart(fig6, use_container_width=True)

    with c7:
        st.markdown("#### Classification Breakdown")
        tp_count = int(alert_sum.get("true_positives", 0))
        fp_count = int(alert_sum.get("false_positives", 0))
        unc_count = int(alert_sum.get("alerts_generated", 0)) - tp_count - fp_count
        fig7 = go.Figure(go.Pie(
            values=[tp_count, fp_count, max(0, unc_count)],
            labels=["True Positive", "False Positive", "Uncertain"],
            marker_colors=["#ef4444", "#22c55e", "#718096"],
            hole=0.5,
        ))
        fig7 = layout_chart(fig7, height=280)
        st.plotly_chart(fig7, use_container_width=True)


# ══════════════════════════════════════════════
# TAB 2 — ALERTS
# ══════════════════════════════════════════════
with tab_alerts:
    st.markdown(f"#### Alert Investigation — {len(df_alerts)} alerts generated")

    if not df_alerts.empty:
        display_cols = ["result_id", "severity", "alert_type", "source_ip", "outcome",
                        "fp_score", "risk_score", "escalate", "true_positive", "false_positive",
                        "hallucinated", "is_campaign", "pipeline_status"]
        avail = [c for c in display_cols if c in df_alerts.columns]
        styled = df_alerts[avail].copy()
        styled = styled.rename(columns={
            "result_id": "ID", "severity": "Sev", "alert_type": "Attack Type",
            "source_ip": "Source IP", "outcome": "Outcome", "fp_score": "FP Score",
            "risk_score": "Risk", "escalate": "Escalate", "true_positive": "TP",
            "false_positive": "FP", "hallucinated": "Halluc",
            "is_campaign": "Campaign", "pipeline_status": "Engine",
        })
        st.dataframe(
            styled, use_container_width=True, hide_index=True,
            column_config={
                "Sev": st.column_config.TextColumn(width="small"),
                "FP Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d"),
                "Risk": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d"),
                "Escalate": st.column_config.CheckboxColumn(width="small"),
                "TP": st.column_config.CheckboxColumn(width="small"),
                "FP": st.column_config.CheckboxColumn(width="small"),
                "Halluc": st.column_config.CheckboxColumn(width="small"),
                "Campaign": st.column_config.CheckboxColumn(width="small"),
            }
        )
    else:
        st.info("No alerts match the current filters.")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    # Alert Detail Inspector
    st.markdown("#### Alert Detail Inspector")
    alert_ids = df_alerts[df_alerts["result_id"].notna()]["result_id"].tolist()

    if alert_ids:
        sel_id = st.selectbox("Select Alert ID", options=alert_ids)
        sel_row = df_alerts[df_alerts["result_id"] == sel_id].iloc[0]

        sev = sel_row.get("severity", "")
        st.markdown(badge(sev), unsafe_allow_html=True)
        st.markdown("")

        col_l, col_r = st.columns(2)

        with col_l:
            st.markdown(f"**Alert ID:** `{sel_id}`")
            st.markdown(f"**Attack Type:** `{sel_row.get('alert_type', 'N/A')}`")
            st.markdown(f"**Source IP:** `{sel_row.get('source_ip', 'N/A')}`")
            st.markdown(f"**Target URL:** `{sel_row.get('target_url', 'N/A') or 'N/A'}`")
            st.markdown(f"**Status Code:** `{sel_row.get('status_code', 'N/A')}`")
            st.markdown(f"**User Agent:** `{str(sel_row.get('user_agent', 'N/A'))[:80]}`")
            st.markdown(f"**Outcome:** `{sel_row.get('outcome', 'N/A')}`")
            st.markdown(f"**FP Score:** `{sel_row.get('fp_score', 'N/A')}/100`")
            st.markdown(fp_bar(int(sel_row.get("fp_score", 50))), unsafe_allow_html=True)
            st.markdown(f"**Risk Score:** `{sel_row.get('risk_score', 'N/A')}/100`")
            st.markdown(f"**Confidence:** `{sel_row.get('confidence', 0):.0%}`")
            st.markdown(f"**Engine:** `{sel_row.get('pipeline_status', 'N/A')}`")
            if sel_row.get("mitre_tactic"):
                st.markdown(f"**MITRE ATT&CK:** `{sel_row.get('mitre_tactic')}` / `{sel_row.get('mitre_t_id', 'N/A')}`")
            if sel_row.get("ti_reputation"):
                st.markdown(f"**Threat Intelligence:** {ti_badge(sel_row.get('ti_reputation', ''))}", unsafe_allow_html=True)
            if sel_row.get("soar_ticket"):
                st.markdown(f"**SOAR Ticket:** `{sel_row.get('soar_ticket')}`")

        with col_r:
            st.markdown("**Alert Summary:**")
            st.info(sel_row.get("summary", "No summary available"))

            evidence = sel_row.get("evidence", [])
            if evidence:
                st.markdown("**Attack Evidence:**")
                for ev in evidence:
                    st.markdown(f'<div class="code-block">{ev}</div>', unsafe_allow_html=True)

            actions = sel_row.get("actions", [])
            if actions:
                st.markdown("**Recommended Actions:**")
                for a in actions:
                    st.markdown(f"- {a}")

            if sel_row.get("escalate"):
                st.error(f"**ESCALATE TO SOC LEVEL 2**\n\n{sel_row.get('esc_reason', '')}")

            if sel_row.get("is_campaign"):
                st.warning(f"**Campaign Detected**\n\n{sel_row.get('corr_summary', '')}")

            if sel_row.get("hallucinated"):
                flags = sel_row.get("h_flags", [])
                st.warning("**Hallucination Flags**\n\n" + "\n".join(f"- {f}" for f in flags))

        # Raw JSON expander
        with st.expander("Raw Alert JSON"):
            orig = next((r for r in raw_data.get("results", []) if r.get("result_id") == sel_id), {})
            st.json(orig.get("alert", {}))

        with st.expander("Raw Log Data"):
            orig = next((r for r in raw_data.get("results", []) if r.get("result_id") == sel_id), {})
            st.json(orig.get("raw_log", {}))
    else:
        st.info("No alerts with current filters.")


# ══════════════════════════════════════════════
# TAB 3 — CAMPAIGNS
# ══════════════════════════════════════════════
with tab_campaigns:
    st.markdown("#### Multi-Log Attack Campaigns")
    st.markdown("*Correlated multi-step attacks identified across log sources*")

    if campaigns:
        # Campaign overview metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Campaigns", len(campaigns))
        m2.metric("Confirmed Breaches", sum(1 for c in campaigns if "CONFIRMED_BREACH" in c.get("campaign_indicators", [])))
        m3.metric("Brute Force Campaigns", sum(1 for c in campaigns if "BRUTE_FORCE_CAMPAIGN" in c.get("campaign_indicators", [])))
        m4.metric("Multi-Vector Attacks", sum(1 for c in campaigns if "MULTI_VECTOR_ATTACK" in c.get("campaign_indicators", [])))

        st.markdown("")

        # Campaign cards
        for camp in sorted(campaigns, key=lambda x: -x.get("correlation_risk_score", 0)):
            risk = camp.get("correlation_risk_score", 0)
            color = "#ef4444" if risk >= 75 else "#f97316" if risk >= 50 else "#eab308"
            indicators = camp.get("campaign_indicators", [])

            with st.expander(
                f"Campaign: {camp.get('source_ip', '?')} — Risk Score: {risk}/100 — "
                f"{len(indicators)} indicators: {', '.join(indicators[:2])}"
            ):
                cc1, cc2 = st.columns(2)
                with cc1:
                    st.markdown(f"**Source IP:** `{camp.get('source_ip')}`")
                    st.markdown(f"**Log Count:** `{camp.get('log_count')}`")
                    st.markdown(f"**Attack Types:** `{', '.join(camp.get('attack_types', []))}`")
                    st.markdown(f"**Correlation Risk:** `{risk}/100`")
                    st.markdown(f"**Successful Request:** `{camp.get('has_successful_request')}`")
                    st.markdown(f"**Failed Logins:** `{camp.get('failed_login_count', 0)}`")
                with cc2:
                    st.markdown("**Campaign Indicators:**")
                    for ind in indicators:
                        badge_color = "#7f1d1d" if "BREACH" in ind else "#3d2608" if "EXPLOIT" in ind else "#1e3a5f"
                        st.markdown(
                            f'<span style="background:{badge_color};color:#fff;padding:2px 8px;'
                            f'border-radius:4px;font-size:0.7rem;margin:2px;display:inline-block">'
                            f'{ind}</span>',
                            unsafe_allow_html=True
                        )
                    st.markdown(f"\n**Summary:**\n{camp.get('correlation_summary', '')}")

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

        # Campaign risk scatter
        st.markdown("#### Campaign Risk Analysis")
        camp_df = pd.DataFrame(campaigns)
        if not camp_df.empty and "correlation_risk_score" in camp_df.columns:
            camp_df["indicators_str"] = camp_df["campaign_indicators"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else str(x)
            )
            fig_camp = px.scatter(
                camp_df,
                x="log_count", y="correlation_risk_score",
                size="log_count", color="correlation_risk_score",
                hover_name="source_ip", hover_data=["indicators_str"],
                color_continuous_scale=["#22c55e", "#eab308", "#ef4444"],
                labels={"log_count": "Log Count", "correlation_risk_score": "Risk Score"},
            )
            fig_camp = layout_chart(fig_camp, "Campaign Risk vs Log Volume", height=320)
            st.plotly_chart(fig_camp, use_container_width=True)
    else:
        st.info("No correlated campaigns detected in current results.")


# ══════════════════════════════════════════════
# TAB 4 — MITRE ATT&CK
# ══════════════════════════════════════════════
with tab_mitre:
    st.markdown("#### MITRE ATT&CK Framework Coverage")

    if not df_alerts.empty and df_alerts["mitre_tactic"].notna().any():

        # Tactic distribution bar
        tactic_counts = df_alerts["mitre_tactic"].dropna().value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Count"]

        fig_mitre = px.bar(
            tactic_counts, x="Tactic", y="Count",
            color="Count", color_continuous_scale=["#1e3a5f", "#3b82f6", "#ef4444"],
            labels={"Tactic": "ATT&CK Tactic", "Count": "Alert Count"},
        )
        fig_mitre.update_coloraxes(showscale=False)
        fig_mitre = layout_chart(fig_mitre, "Alerts by ATT&CK Tactic", height=300)
        st.plotly_chart(fig_mitre, use_container_width=True)

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

        # Technique heatmap
        st.markdown("#### Technique Severity Matrix")
        heat_data = df_alerts[df_alerts["mitre_technique"].notna()].copy()
        if not heat_data.empty:
            heat_pivot = heat_data.groupby(["mitre_technique", "severity"]).size().reset_index(name="count")
            heat_pivot_wide = heat_pivot.pivot(index="mitre_technique", columns="severity", values="count").fillna(0)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev not in heat_pivot_wide.columns:
                    heat_pivot_wide[sev] = 0
            heat_pivot_wide = heat_pivot_wide[["CRITICAL", "HIGH", "MEDIUM", "LOW"]]

            fig_heat = go.Figure(go.Heatmap(
                z=heat_pivot_wide.values,
                x=heat_pivot_wide.columns.tolist(),
                y=heat_pivot_wide.index.tolist(),
                colorscale=[[0, "#0f1117"], [0.3, "#1e3a5f"], [0.6, "#f97316"], [1, "#ef4444"]],
                text=heat_pivot_wide.values,
                texttemplate="%{text:.0f}",
            ))
            fig_heat.update_layout(
                paper_bgcolor=PLOT_BG, plot_bgcolor=PLOT_BG, font_color=FONT_CLR,
                margin=dict(t=20, b=20, l=10, r=10), height=max(250, len(heat_pivot_wide) * 35),
                xaxis_title="Severity Level", yaxis_title="Technique",
            )
            st.plotly_chart(fig_heat, use_container_width=True)

        # Technique table
        st.markdown("#### MITRE ATT&CK Technique Reference")
        tech_df = df_alerts[df_alerts["mitre_tactic"].notna()][
            ["alert_type", "mitre_tactic", "mitre_tactic_id", "mitre_technique", "mitre_t_id", "severity"]
        ].drop_duplicates().sort_values("mitre_tactic")
        st.dataframe(tech_df, use_container_width=True, hide_index=True)

    else:
        st.info("No MITRE ATT&CK data available in current results.")


# ══════════════════════════════════════════════
# TAB 5 — THREAT INTEL
# ══════════════════════════════════════════════
with tab_ti:
    st.markdown("#### Threat Intelligence Enrichment")

    ti_alerts = df_full[df_full["ti_reputation"].isin(["MALICIOUS", "SUSPICIOUS"])].copy()
    ti_all = df_full[df_full["ti_reputation"].notna() & (df_full["ti_reputation"] != "")].copy()

    ti_m1, ti_m2, ti_m3 = st.columns(3)
    ti_m1.metric("Enriched IPs", len(ti_all["source_ip"].dropna().unique()))
    ti_m2.metric("Malicious IPs", len(ti_all[ti_all["ti_reputation"] == "MALICIOUS"]["source_ip"].dropna().unique()))
    ti_m3.metric("Suspicious IPs", len(ti_all[ti_all["ti_reputation"] == "SUSPICIOUS"]["source_ip"].dropna().unique()))

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    if not ti_alerts.empty:
        st.markdown("#### High-Risk IP Analysis")
        ti_display = ti_alerts.groupby("source_ip").agg(
            reputation=("ti_reputation", "first"),
            ti_score=("ti_score", "first"),
            alert_count=("is_alert", "sum"),
            attack_types=("alert_type", lambda x: ", ".join(sorted(set(x.dropna())))),
        ).reset_index().sort_values("ti_score", ascending=False)

        for _, row in ti_display.iterrows():
            rep_html = ti_badge(row["reputation"])
            with st.expander(f"{row['source_ip']} — {row.get('attack_types', 'N/A')} — Score: {row.get('ti_score', 0)}/100"):
                tc1, tc2 = st.columns(2)
                tc1.markdown(f"**IP Address:** `{row['source_ip']}`")
                tc1.markdown(f"**Reputation:** {rep_html}", unsafe_allow_html=True)
                tc1.markdown(f"**Threat Score:** `{row.get('ti_score', 0)}/100`")
                tc1.markdown(f"**Alert Count:** `{int(row.get('alert_count', 0))}`")
                tc2.markdown(f"**Attack Types:** `{row.get('attack_types', 'N/A')}`")

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

        # TI score distribution
        ti_score_data = ti_all[ti_all["ti_score"] > 0][["source_ip", "ti_score", "ti_reputation"]].drop_duplicates("source_ip")
        if not ti_score_data.empty:
            fig_ti = px.bar(
                ti_score_data.sort_values("ti_score", ascending=False),
                x="source_ip", y="ti_score",
                color="ti_reputation",
                color_discrete_map={"MALICIOUS": "#ef4444", "SUSPICIOUS": "#f97316", "CLEAN": "#22c55e"},
                labels={"source_ip": "IP Address", "ti_score": "Threat Score"},
            )
            fig_ti = layout_chart(fig_ti, "Threat Intelligence Scores by IP", height=300)
            st.plotly_chart(fig_ti, use_container_width=True)
    else:
        st.info("No threat intelligence hits in current results. Set ABUSEIPDB_API_KEY environment variable to enable.")


# ══════════════════════════════════════════════
# TAB 6 — SOAR
# ══════════════════════════════════════════════
with tab_soar:
    st.markdown("#### SOAR Automated Response")
    st.markdown("*Security Orchestration, Automation and Response*")

    soar_alerts = df_alerts[df_alerts["soar_playbook"].notna() & (df_alerts["soar_playbook"] != "")].copy()

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Playbooks Triggered", len(soar_alerts))
    s2.metric("Auto-Escalated", int(soar_alerts["soar_escalate"].sum()))
    s3.metric("Tickets Generated", int(soar_alerts["soar_ticket"].notna().sum()))
    s4.metric("Avg SLA (minutes)", int(soar_alerts["soar_sla"].mean()) if not soar_alerts.empty else "N/A")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    if not soar_alerts.empty:
        st.markdown("#### Active SOAR Tickets")
        ticket_display = soar_alerts[["soar_ticket", "severity", "alert_type", "source_ip",
                                      "soar_playbook", "soar_escalate", "soar_sla"]].copy()
        ticket_display = ticket_display.rename(columns={
            "soar_ticket": "Ticket ID", "severity": "Priority", "alert_type": "Attack Type",
            "source_ip": "IP Address", "soar_playbook": "Playbook", "soar_escalate": "Auto-Escalate",
            "soar_sla": "SLA (min)",
        })
        st.dataframe(ticket_display, use_container_width=True, hide_index=True,
                     column_config={
                         "Auto-Escalate": st.column_config.CheckboxColumn(width="small"),
                     })

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

        # Playbook distribution
        pb_counts = soar_alerts["soar_playbook"].value_counts().reset_index()
        pb_counts.columns = ["Playbook", "Count"]
        fig_pb = px.bar(pb_counts, x="Count", y="Playbook", orientation="h",
                        color="Count", color_continuous_scale=["#1e3a5f", "#3b82f6", "#ef4444"])
        fig_pb.update_coloraxes(showscale=False)
        fig_pb = layout_chart(fig_pb, "Playbook Distribution", height=max(200, len(pb_counts) * 40))
        st.plotly_chart(fig_pb, use_container_width=True)
    else:
        st.info("No SOAR responses recorded. Re-run pipeline with SOAR engine enabled.")


# ══════════════════════════════════════════════
# TAB 7 — EVALUATION
# ══════════════════════════════════════════════
with tab_eval:
    st.markdown("#### Alert Quality Evaluation")

    if eval_data:
        ev_sum = eval_data.get("summary", {})
        ev_meta = eval_data.get("metadata", {})

        e1, e2, e3, e4 = st.columns(4)
        e1.metric("Avg Quality Score", f"{ev_sum.get('avg_quality_score', 0)}/10")
        e2.metric("Alerts Evaluated", ev_sum.get("alerts_generated", 0))
        e3.metric("True Positives", ev_sum.get("true_positives", 0))
        e4.metric("False Positives", ev_sum.get("false_positives", 0))

        scored = eval_data.get("scored_results", [])
        if scored:
            score_df = pd.DataFrame([{
                "result_id": s.get("result_id", ""),
                "log_index": s.get("log_index"),
                "alert_type": s.get("alert_type", ""),
                "severity": s.get("severity", ""),
                "score_10": s.get("score_10", 0),
                "fp_score": s.get("fp_score", 50),
                "risk_score": s.get("risk_score", 0),
                "is_campaign": s.get("is_campaign", False),
            } for s in scored if s.get("is_alert")])

            if not score_df.empty:
                st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

                # Score bar chart
                fig_sc = px.bar(
                    score_df.sort_values("score_10"),
                    x="result_id", y="score_10",
                    color="severity", color_discrete_map=SEV_COLOR,
                    range_y=[0, 10],
                    labels={"score_10": "Quality Score (/10)", "result_id": "Alert ID"},
                )
                fig_sc = layout_chart(fig_sc, "Alert Quality Scores", height=320)
                st.plotly_chart(fig_sc, use_container_width=True)

                # Score vs FP scatter
                fig_sc2 = px.scatter(
                    score_df, x="fp_score", y="score_10",
                    color="severity", color_discrete_map=SEV_COLOR,
                    hover_data=["alert_type", "result_id"],
                    labels={"fp_score": "False Positive Score", "score_10": "Quality Score (/10)"},
                    size=[8] * len(score_df),
                )
                fig_sc2 = layout_chart(fig_sc2, "Quality Score vs False Positive Score", height=300)
                st.plotly_chart(fig_sc2, use_container_width=True)

                # Breakdown table for worst alerts
                st.markdown("#### Low-Score Alert Analysis")
                worst = sorted(scored, key=lambda s: s.get("score_10", 10))[:5]
                for w in worst:
                    with st.expander(f"[{w.get('score_10', 0)}/10] Log #{w.get('log_index')} — {w.get('alert_type', '')} — {w.get('source_ip', '')}"):
                        bd = w.get("breakdown", {})
                        bd_df = pd.DataFrame([{
                            "Dimension": k,
                            "Score": v.get("score", 0),
                            "Max": v.get("max", 0),
                            "Reason": v.get("reason", ""),
                        } for k, v in bd.items()])
                        bd_df["Percentage"] = (bd_df["Score"] / bd_df["Max"] * 100).round(0)
                        st.dataframe(bd_df, use_container_width=True, hide_index=True,
                                     column_config={
                                         "Percentage": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d%%"),
                                     })
    else:
        st.info("No evaluation report found. Run: python evaluateur_complet.py --input data/results_docker.json")

    st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

    # Hallucination analysis
    st.markdown("#### LLM Hallucination Analysis")
    h_stats = raw_data.get("statistics", {}).get("hallucination_stats", {})
    if h_stats:
        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Total Alerts", h_stats.get("total_alerts", 0))
        h2.metric("Hallucinated", h_stats.get("hallucinated_alerts", 0))
        h3.metric("Hallucination Rate", f"{h_stats.get('hallucination_rate', 0)}%")
        h4.metric("Total Flags", h_stats.get("total_flags", 0))

        h_alerts_df = df_alerts[df_alerts["hallucinated"] == True].copy()
        if not h_alerts_df.empty:
            st.markdown("**Alerts with Hallucination Flags:**")
            h_display = h_alerts_df[["result_id", "alert_type", "severity", "source_ip", "h_score", "h_flags"]].copy()
            h_display["h_flags"] = h_display["h_flags"].apply(
                lambda x: " | ".join(x) if isinstance(x, list) else str(x)
            )
            h_display = h_display.rename(columns={"h_score": "Hallucination Score", "h_flags": "Flags"})
            st.dataframe(h_display, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════
# TAB 8 — FEEDBACK LOOP
# ══════════════════════════════════════════════
with tab_feedback:
    st.markdown("#### Analyst Feedback Loop")
    st.markdown("*Override AI classifications to calibrate false positive detection*")

    # Load feedback module
    try:
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from feedback_loop import get_feedback_loop
        fb = get_feedback_loop()
        fb_available = True
    except Exception:
        fb_available = False

    if fb_available:
        fb_stats = fb.get_stats()
        f1, f2, f3, f4 = st.columns(4)
        f1.metric("Total Feedback", fb_stats.get("total_feedback", 0))
        f2.metric("Analyst True Positives", fb_stats.get("analyst_tps", 0))
        f3.metric("Analyst False Positives", fb_stats.get("analyst_fps", 0))
        f4.metric("Uncertain", fb_stats.get("analyst_uncertain", 0))

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)
        st.markdown("#### Submit Analyst Verdict")

        feedback_alert_ids = df_alerts[df_alerts["result_id"].notna()]["result_id"].tolist()
        if feedback_alert_ids:
            fb_col1, fb_col2 = st.columns(2)
            with fb_col1:
                fb_id = st.selectbox("Alert to Review", options=feedback_alert_ids, key="fb_sel")
                fb_verdict = st.radio("Verdict", ["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"],
                                      horizontal=True, key="fb_verdict")
            with fb_col2:
                fb_note = st.text_area("Analyst Note (optional)", key="fb_note", height=100)
                if st.button("Submit Feedback", key="fb_submit", use_container_width=True):
                    sel = df_alerts[df_alerts["result_id"] == fb_id]
                    atype = sel.iloc[0].get("alert_type", "Unknown") if not sel.empty else "Unknown"
                    entry = fb.record_feedback(fb_id, atype, fb_verdict, fb_note)
                    st.success(f"Feedback recorded: {fb_id} -> {fb_verdict}")
                    st.rerun()

        st.markdown('<div class="sep"></div>', unsafe_allow_html=True)

        # Calibration adjustments
        adjustments = fb_stats.get("calibration_adjustments", {})
        if adjustments:
            st.markdown("#### FP Score Calibration Adjustments")
            adj_df = pd.DataFrame(
                [{"Attack Type": k, "FP Adjustment": v} for k, v in adjustments.items()]
            )
            st.dataframe(adj_df, use_container_width=True, hide_index=True)

        # Feedback history
        all_fb = fb.get_all_feedback()
        if all_fb:
            st.markdown("#### Feedback History")
            fb_df = pd.DataFrame(all_fb)
            fb_df = fb_df[["result_id", "alert_type", "analyst_verdict", "analyst_note", "recorded_at"]]
            fb_df = fb_df.rename(columns={
                "result_id": "Alert ID", "alert_type": "Type",
                "analyst_verdict": "Verdict", "analyst_note": "Note", "recorded_at": "Timestamp",
            })
            st.dataframe(fb_df.sort_values("Timestamp", ascending=False).head(50),
                         use_container_width=True, hide_index=True)
    else:
        st.warning("Feedback loop module not found. Ensure feedback_loop.py is in the same directory.")


# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown(
    f"""
    <div class="footer">
        SOC AI Analyst Dashboard — Enterprise Edition v3.0<br>
        Hybrid Rule Engine + LLM (Llama3) + Threat Intelligence + SOAR + Feedback Loop<br>
        MITRE ATT&CK Framework · Anti-Hallucination · Multi-Log Correlation<br>
        Last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
    """,
    unsafe_allow_html=True
)