"""
dashboard_soc.py — SOC AI Analyst Platform v5.1
================================================
Responsibility:
  1. Accept a logs.json upload from the user
  2. Send it to main.py's run_on_logs() pipeline
  3. Pipeline saves results to data/results_docker.json (main.py owns this)
  4. Dashboard reloads from disk and displays the results

The dashboard does NOT store pipeline results in session state.
It simply triggers main.py and then reads the output file.

FIXES vs original:
  FIX-D1 — results_file default now uses the same absolute path as main.py's
            DEFAULT_OUTPUT_FILE so load_results() always finds the file even
            when Streamlit's cwd differs from the project root.
  FIX-D2 — run_on_logs() output_file kwarg passed explicitly so dashboard and
            pipeline always agree on where results land.
  FIX-D3 — probe_ollama() respects OLLAMA_HOST env var (Docker injection).
  FIX-D4 — _progress_cb: progress bar value clamped to [0.0, 1.0] to avoid
            Streamlit ValueError on empty log list (total=0 division).
  FIX-D5 — normalize_results() guards against None/NaN in list-type columns
            (evidence, actions, h_flags, campaign_indicators) so DataFrame
            operations don't crash on partial LLM outputs.
  FIX-D6 — format_timestamp() returns "N/A" for None; previously crashed on
            None input with AttributeError.
  FIX-D7 — soc_evaluator depends_on soc_pipeline which is restart:no; dashboard
            must not assume eval file exists — load_eval already handles missing
            file, no change needed but documented.
  FIX-D8 — sys.path.insert moved inside try block; was clobbering sys.path on
            every Streamlit rerun even when import failed.
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import List
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


st.set_page_config(
    page_title="SOC AI Analyst - Enterprise Platform",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': '# SOC AI Analyst Platform\nVersion 5.1 Enterprise'
    }
)


def init_session_state():
    defaults = {
        'auto_refresh':       False,
        'last_refresh_time':  datetime.now(),
        'refresh_interval':   60,
        'user_role':          'soc_analyst',
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


def load_enterprise_css():
    st.markdown("""
    <style>
    :root {
        --primary: #2563eb; --primary-dark: #1d4ed8; --primary-light: #3b82f6;
        --success: #10b981; --warning: #f59e0b; --danger: #ef4444; --info: #06b6d4;
        --bg-primary: #0a0c10; --bg-secondary: #0f1117; --bg-tertiary: #1a1d26;
        --bg-card: #13161d; --text-primary: #e2e8f0; --text-secondary: #94a3b8;
        --text-muted: #64748b; --border-light: #1e2433; --border-medium: #2d3748;
    }
    .stApp { background: var(--bg-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
    .enterprise-header {
        background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-card) 100%);
        border-bottom: 2px solid var(--primary); padding: 1.5rem 2rem;
        margin-bottom: 2rem; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
    }
    .header-title { font-size: 1.5rem; font-weight: 500; color: var(--text-primary); letter-spacing: -0.02em; }
    .header-subtitle { color: var(--text-secondary); font-size: 0.8rem; }
    .header-badge { background: var(--primary-dark); color: var(--text-primary); padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.7rem; font-weight: 500; display: inline-block; }
    .metric-card { background: var(--bg-card); border: 1px solid var(--border-light); padding: 1rem; transition: all 0.2s ease; }
    .metric-card:hover { border-color: var(--primary); transform: translateY(-1px); }
    .metric-label { color: var(--text-secondary); font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem; }
    .metric-value { color: var(--text-primary); font-size: 1.8rem; font-weight: 600; line-height: 1.2; }
    .status-critical { background: rgba(239,68,68,0.1); border-left: 3px solid var(--danger); padding: 0.5rem 1rem; color: #fca5a5; font-size: 0.8rem; }
    .status-warning { background: rgba(245,158,11,0.1); border-left: 3px solid var(--warning); padding: 0.5rem 1rem; color: #fcd34d; font-size: 0.8rem; }
    .status-success { background: rgba(16,185,129,0.1); border-left: 3px solid var(--success); padding: 0.5rem 1rem; color: #6ee7b7; font-size: 0.8rem; }
    .alert-severity { padding: 0.2rem 0.6rem; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
    .severity-critical { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid var(--danger); }
    .severity-high { background: rgba(245,158,11,0.2); color: #fcd34d; border: 1px solid var(--warning); }
    .severity-medium { background: rgba(245,158,11,0.1); color: #fde68a; border: 1px solid #d97706; }
    .severity-low { background: rgba(16,185,129,0.1); color: #6ee7b7; border: 1px solid var(--success); }
    .badge { display: inline-flex; align-items: center; padding: 0.2rem 0.5rem; font-size: 0.7rem; font-weight: 600; }
    .badge-danger { background: var(--danger); color: white; }
    .badge-warning { background: var(--warning); color: black; }
    .badge-success { background: var(--success); color: white; }
    .code-block { background: var(--bg-secondary); border: 1px solid var(--border-light); border-radius: 4px; padding: 0.5rem 0.75rem; font-family: 'SF Mono', monospace; font-size: 0.7rem; color: var(--text-primary); overflow-x: auto; }
    .section-divider { border-top: 1px solid var(--border-light); margin: 1.5rem 0; }
    .enterprise-footer { margin-top: 2rem; padding: 1rem; text-align: center; border-top: 1px solid var(--border-light); color: var(--text-muted); font-size: 0.7rem; }
    [data-testid="stSidebar"] { background: var(--bg-secondary); border-right: 1px solid var(--border-light); }
    [data-testid="stTabs"] { gap: 0.25rem; }
    [data-testid="stTabs"] button { color: var(--text-secondary); font-weight: 500; font-size: 0.8rem; padding: 0.4rem 1rem; border-radius: 4px; transition: all 0.2s ease; }
    [data-testid="stTabs"] button:hover { color: var(--text-primary); background: rgba(37,99,235,0.07); }
    [data-testid="stTabs"] button[aria-selected="true"] { color: var(--text-primary); background: rgba(37,99,235,0.1); border-bottom: 2px solid var(--primary); }
    [data-testid="stButton"] button { background: var(--primary); color: white; border: none; border-radius: 4px; padding: 0.4rem 1rem; font-weight: 500; font-size: 0.8rem; transition: all 0.2s ease; }
    [data-testid="stButton"] button:hover { background: var(--primary-dark); transform: translateY(-1px); }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-tertiary); }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 3px; }
    </style>
    """, unsafe_allow_html=True)

load_enterprise_css()

SEVERITY_CONFIG = {
    "CRITICAL": {"color": "#ef4444", "weight": 4},
    "HIGH":     {"color": "#f59e0b", "weight": 3},
    "MEDIUM":   {"color": "#eab308", "weight": 2},
    "LOW":      {"color": "#10b981", "weight": 1},
}

# ── FIX-D1: Resolve results path the same way main.py does ───────────────────
_DASHBOARD_DIR       = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_RESULTS     = os.path.join(_DASHBOARD_DIR, "data", "results_docker.json")
_DEFAULT_EVAL        = os.path.join(_DASHBOARD_DIR, "data", "evaluation_report.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def format_timestamp(ts) -> str:
    # FIX-D6: guard against None / non-string input
    if not ts:
        return "N/A"
    ts = str(ts)
    try:
        dt = (datetime.fromisoformat(ts.replace('Z', '+00:00'))
              if 'Z' in ts else datetime.fromisoformat(ts))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts[:19]

def badge(sev: str) -> str:
    sev = sev or "LOW"
    cls = f"severity-{sev.lower()}" if sev.lower() in ("critical","high","medium","low") else "severity-low"
    return f'<span class="alert-severity {cls}">{sev}</span>'

def ti_badge(rep: str) -> str:
    rep = (rep or "").upper()
    if rep == "MALICIOUS":  return '<span class="badge badge-danger">MALICIOUS</span>'
    if rep == "SUSPICIOUS": return '<span class="badge badge-warning">SUSPICIOUS</span>'
    return '<span class="badge badge-success">CLEAN</span>'

def probe_ollama() -> tuple[bool, str]:
    """
    Probe Ollama. Checks OLLAMA_HOST env first (FIX-D3), then falls back to
    known Docker service name and localhost.
    """
    try:
        import requests as _req
        candidates = []
        env_host = os.environ.get("OLLAMA_HOST", "").strip()
        if env_host:
            candidates.append(env_host.rstrip("/"))
        # Docker service name always present in compose network
        candidates += ["http://ollama:11434", "http://localhost:11434"]
        # Deduplicate while preserving order
        seen = set()
        candidates = [c for c in candidates if not (c in seen or seen.add(c))]
        for host in candidates:
            try:
                r = _req.get(f"{host}/api/tags", timeout=3)
                if r.status_code == 200:
                    return True, host
            except Exception:
                continue
    except Exception:
        pass
    return False, "unavailable"


@st.cache_data(ttl=30, show_spinner=False)
def load_results(path: str) -> dict:
    try:
        if not Path(path).exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading results: {e}")
        return {}

@st.cache_data(ttl=300, show_spinner=False)
def load_eval(path: str) -> dict:
    try:
        if not Path(path).exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _safe_list(val) -> list:
    """FIX-D5: ensure list-type alert fields are always a Python list."""
    if isinstance(val, list):
        return val
    if val is None or (isinstance(val, float) and pd.isna(val)):
        return []
    return []

def normalize_results(raw_data: dict) -> pd.DataFrame:
    rows = []
    for r in raw_data.get("results", []):
        alert = r.get("alert", {}) or {}
        corr  = r.get("correlation", {}) or {}
        ti    = r.get("threat_intel", {}) or {}
        soar  = alert.get("soar_response", {}) or {}
        rows.append({
            "result_id":         r.get("result_id"),
            "log_index":         r.get("log_index"),
            "log_type":          r.get("log_type", "unknown"),
            "source_ip":         r.get("source_ip"),
            "timestamp":         r.get("timestamp"),
            "pipeline_status":   r.get("status", ""),
            "is_alert":          bool(alert.get("is_alert", False)),
            "alert_type":        alert.get("alert_type", ""),
            "severity":          alert.get("severity", ""),
            "severity_weight":   SEVERITY_CONFIG.get(alert.get("severity", "MEDIUM"), {}).get("weight", 2),
            "fp_score":          alert.get("false_positive_score", 50),
            "risk_score":        alert.get("risk_score", 0),
            "confidence":        alert.get("confidence", 0),
            "true_positive":     bool(alert.get("true_positive", False)),
            "false_positive":    bool(alert.get("false_positive", False)),
            "outcome":           alert.get("outcome", ""),
            "summary":           alert.get("summary", ""),
            "target_url":        alert.get("target_url", ""),
            "user":              alert.get("user", ""),
            "user_agent":        alert.get("user_agent", ""),
            "status_code":       alert.get("status_code", ""),
            "mitre_tactic":      alert.get("mitre_tactic", ""),
            "mitre_tactic_id":   alert.get("mitre_tactic_id", ""),
            "mitre_technique":   alert.get("mitre_technique", ""),
            "mitre_t_id":        alert.get("mitre_technique_id", ""),
            "escalate":          bool(alert.get("escalate_to_soc_level2", False)),
            "esc_reason":        alert.get("escalation_reason", ""),
            "hallucinated":      bool(alert.get("hallucination_detected", False)),
            "h_flags":           _safe_list(alert.get("hallucination_flags")),
            "h_score":           alert.get("hallucination_score", 0),
            "actions":           _safe_list(alert.get("recommended_actions")),
            "evidence":          _safe_list(alert.get("attack_evidence")),
            "fp_reason":         alert.get("false_positive_reason", ""),
            "is_campaign":       bool(corr.get("is_campaign", False)),
            "campaign_indicators": _safe_list(corr.get("campaign_indicators")),
            "corr_risk":         corr.get("correlation_risk_score", 0),
            "corr_summary":      corr.get("correlation_summary", ""),
            "ti_reputation":     ti.get("reputation", ""),
            "ti_score":          ti.get("threat_score", 0),
            "soar_playbook":     soar.get("playbook_name", ""),
            "soar_escalate":     bool(soar.get("auto_escalate", False)),
            "soar_ticket":       (soar.get("ticket") or {}).get("ticket_id", ""),
            "soar_sla":          soar.get("sla_response_minutes", 60),
            "rule_matched":      alert.get("rule_matched", ""),
            "alert_type_source": alert.get("alert_type_source", ""),
            "created_at":        datetime.now(),
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ── Sidebar ───────────────────────────────────────────────────────────────────
_ollama_online, _ollama_host = probe_ollama()

with st.sidebar:
    st.markdown("""
    <div style="padding:1rem 0;border-bottom:1px solid #1e2433;margin-bottom:1rem;">
        <h2 style="color:#e2e8f0;margin:0;font-size:1.2rem;font-weight:500;">SOC PLATFORM</h2>
        <p style="color:#94a3b8;margin:0;font-size:0.7rem;">Enterprise Edition v5.1</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Step 1 — Upload Logs")
    uploaded_logs = st.file_uploader(
        "Upload logs.json",
        type=["json"],
        key="log_uploader",
        help="JSON array of log entries. Pipeline will analyse and save results automatically.",
    )

    if _ollama_online:
        st.markdown(
            f'<div class="status-success" style="margin:0.5rem 0;">&#10003; Ollama — Online '
            f'<code>{_ollama_host}</code></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="status-warning" style="margin:0.5rem 0;">&#9888; Ollama — Offline<br>'
            'Pipeline will use rule engine only.<br>'
            'Set <code>OLLAMA_HOST</code> env var if Ollama runs elsewhere.</div>',
            unsafe_allow_html=True,
        )

    use_llm = st.checkbox(
        "Enable LLM fallback (requires Ollama)",
        value=_ollama_online,
        key="use_llm_toggle",
        help="When enabled, logs with no rule match are sent to LLM (compact prompt — fast).",
    )

    if uploaded_logs is not None:
        if st.button("▶  Analyse Logs", use_container_width=True, key="run_btn"):
            st.session_state["_run_pipeline"] = True
            st.session_state["_log_bytes"]    = uploaded_logs.read()
            st.rerun()

    st.markdown("---")

    st.markdown("### Step 2 — View Results")
    # FIX-D1: default to absolute path so it matches main.py's DEFAULT_OUTPUT_FILE
    results_file = st.text_input("Results file", value=_DEFAULT_RESULTS)
    eval_file    = st.text_input("Evaluation report", value=_DEFAULT_EVAL)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("⟳ Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    with col2:
        if st.button("✕ Clear cache", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    st.markdown("---")
    st.markdown("### Filters")

    raw_data  = load_results(results_file)
    eval_data = load_eval(eval_file)

    if raw_data:
        df_full = normalize_results(raw_data)
        if df_full.empty:
            st.warning("Results loaded but no rows parsed.")
            sev_filter = type_filter = outcome_filt = ti_filter = "ALL"
            esc_only = camp_only = tp_only = halluc_only = False
        else:
            df_full["is_alert"] = df_full["is_alert"].fillna(False)

            sev_filter   = st.selectbox("Severity",     ["ALL","CRITICAL","HIGH","MEDIUM","LOW"], index=0)
            all_types    = ["ALL"] + sorted(df_full[df_full["is_alert"]]["alert_type"].dropna().unique().tolist())
            type_filter  = st.selectbox("Attack Type",  all_types, index=0)
            all_outcomes = ["ALL"] + sorted(df_full["outcome"].dropna().unique().tolist())
            outcome_filt = st.selectbox("Outcome",      all_outcomes, index=0)
            ti_filter    = st.selectbox("Threat Intel", ["ALL","MALICIOUS","SUSPICIOUS","CLEAN"], index=0)

            st.markdown("#### Quick Filters")
            esc_only    = st.checkbox("Escalated Only")
            camp_only   = st.checkbox("Campaigns Only")
            tp_only     = st.checkbox("True Positives Only")
            halluc_only = st.checkbox("Hallucinations Only")
    else:
        sev_filter = type_filter = outcome_filt = ti_filter = "ALL"
        esc_only = camp_only = tp_only = halluc_only = False
        df_full = pd.DataFrame()

    st.markdown("---")
    if raw_data:
        meta  = raw_data.get("metadata", {})
        stats = raw_data.get("statistics", {})
        st.markdown("### System Metrics")
        st.metric("Processing Time",  f"{stats.get('duration_sec', 0):.1f}s")
        st.metric("Active Campaigns", len(raw_data.get("campaigns", [])))
        st.metric("LLM Engine",       "Online ✓" if _ollama_online else "Offline ✗")
        st.metric("Version",          meta.get("version", "N/A"))

    st.markdown("---")
    st.markdown("""
    <div style="font-size:0.65rem;color:#64748b;text-align:center;">
        SOC AI Analyst Platform<br>Enterprise Edition v5.1
    </div>
    """, unsafe_allow_html=True)


# ── Pipeline execution ────────────────────────────────────────────────────────
if st.session_state.get("_run_pipeline"):
    raw_bytes = st.session_state.pop("_log_bytes", None)
    st.session_state["_run_pipeline"] = False

    if raw_bytes:
        try:
            raw_logs = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(raw_logs, list):
                st.error("Invalid format: logs.json must be a JSON array.")
                st.stop()
        except Exception as e:
            st.error(f"Failed to parse logs.json: {e}")
            st.stop()

        # FIX-D8: sys.path manipulation inside try, not at module level
        try:
            _pipeline_dir = os.path.dirname(os.path.abspath(__file__))
            if _pipeline_dir not in sys.path:
                sys.path.insert(0, _pipeline_dir)
            from main import run_on_logs
        except ImportError as e:
            st.error(
                f"**Pipeline import failed:** `{e}`\n\n"
                "Ensure all pipeline modules are present: "
                "`main.py`, `chain.py`, `log_parser.py`, `hallucination_guard.py`, "
                "`rag_engine.py`, `threat_intel.py`, `soar_engine.py`"
            )
            st.stop()

        st.markdown('<div class="status-warning">Pipeline running — analysing logs…</div>', unsafe_allow_html=True)

        progress_bar  = st.progress(0.0, text="Initialising…")
        status_el     = st.empty()
        live_table_el = st.empty()
        _live_alerts: List[dict] = []

        _use_llm = st.session_state.get("use_llm_toggle", _ollama_online)

        def _progress_cb(done: int, total: int, result: dict):
            # FIX-D4: clamp progress value to avoid ValueError on edge cases
            pct   = min(1.0, max(0.0, done / total)) if total > 0 else 0.0
            alert = result.get("alert", {}) or {}
            eng   = result.get("status", "")
            sev   = alert.get("severity", "")
            atype = alert.get("alert_type", "CLEAN")
            icon  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            progress_bar.progress(pct, text=f"Log {done}/{total} — {eng}")
            status_el.markdown(
                f"`[{done}/{total}]` {icon} **{atype}** — `{eng}` — IP: `{result.get('source_ip') or 'N/A'}`"
            )
            if alert.get("is_alert"):
                _live_alerts.append({
                    "Log#":     done,
                    "Engine":   eng,
                    "Severity": sev,
                    "Type":     atype,
                    "IP":       result.get("source_ip") or "N/A",
                    "Rule":     alert.get("rule_matched", "LLM"),
                })
                live_table_el.dataframe(
                    pd.DataFrame(_live_alerts).tail(10),
                    use_container_width=True,
                    hide_index=True,
                )

        try:
            # FIX-D2: pass output_file explicitly so dashboard and pipeline agree
            run_on_logs(
                raw_logs,
                use_llm=_use_llm,
                progress_callback=_progress_cb,
                output_file=results_file,   # ← explicit, matches sidebar path
            )
        except Exception as exc:
            progress_bar.empty()
            status_el.empty()
            st.error(f"Pipeline error: {exc}")
            import traceback
            st.code(traceback.format_exc(), language="python")
            st.stop()

        progress_bar.progress(1.0, text="Analysis complete.")
        status_el.empty()
        st.cache_data.clear()
        st.success(f"Analysis complete — results saved to `{results_file}`. Refreshing…")
        time.sleep(1)
        st.rerun()


# ── Main display ──────────────────────────────────────────────────────────────
if not raw_data:
    st.markdown("""
    <div class="status-warning" style="margin:2rem 0;">
        No results loaded.<br><br>
        <strong>Option A:</strong> Upload a <code>logs.json</code> file → click <em>Analyse Logs</em><br>
        <strong>Option B:</strong> Point <em>Results file</em> to an existing pipeline output and click <em>Refresh</em>
    </div>
    """, unsafe_allow_html=True)
    st.stop()


df_full = normalize_results(raw_data)
if df_full.empty:
    st.warning("Results file loaded but contained no processable entries.")
    st.stop()

df_full["is_alert"] = df_full["is_alert"].fillna(False)

# Apply filters
df = df_full.copy()
if sev_filter   != "ALL": df = df[df["severity"]      == sev_filter]
if type_filter  != "ALL": df = df[df["alert_type"]    == type_filter]
if outcome_filt != "ALL": df = df[df["outcome"]       == outcome_filt]
if ti_filter    != "ALL": df = df[df["ti_reputation"] == ti_filter]
if esc_only:              df = df[df["escalate"]       == True]
if camp_only:             df = df[df["is_campaign"]    == True]
if tp_only:               df = df[df["true_positive"]  == True]
if halluc_only:           df = df[df["hallucinated"]   == True]

df_alerts = df[df["is_alert"] == True].copy()

# NO_ENGINE diagnostic
_engine_dist   = raw_data.get("statistics", {}).get("engine_distribution", {})
_total_logs    = raw_data.get("statistics", {}).get("total_logs_analysed", 1) or 1
_no_engine_cnt = _engine_dist.get("NO_ENGINE", 0)
if _no_engine_cnt > 0 and (_no_engine_cnt / _total_logs) > 0.5:
    if not raw_data.get("metadata", {}).get("llm_available", False):
        st.markdown(f"""
        <div class="status-warning" style="margin-bottom:1.5rem;">
            <strong>⚠ {_no_engine_cnt}/{_total_logs} logs → NO_ENGINE</strong><br>
            Ollama was offline during analysis. Start Ollama, re-upload logs.json,
            and click <em>Analyse Logs</em>.
        </div>
        """, unsafe_allow_html=True)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="enterprise-header">
    <div>
        <div class="header-title">Security Operations Center</div>
        <div class="header-subtitle">AI-Powered Threat Detection — Fast LLM + Rule Engine Pipeline</div>
    </div>
    <div style="display:flex;gap:1rem;align-items:center;">
        <div class="header-badge">Analyst: {st.session_state.user_role.upper()}</div>
        <div class="header-badge">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── KPI Cards ─────────────────────────────────────────────────────────────────
alert_sum    = raw_data.get("statistics", {}).get("alert_summary", {})
n_critical   = len(df_full[df_full["severity"] == "CRITICAL"])
n_escalated  = len(df_full[df_full["escalate"] == True])
n_campaigns  = len(raw_data.get("campaigns", []))
n_ti_bad     = len(df_full[df_full["ti_reputation"] == "MALICIOUS"])
total_alerts = alert_sum.get("alerts_generated", 0)

c1, c2, c3, c4, c5, c6 = st.columns(6)
for col, label, value, color in [
    (c1, "LOGS ANALYZED",     f"{len(df_full):,}",  "var(--text-primary)"),
    (c2, "ALERTS GENERATED",  f"{total_alerts:,}",  "var(--text-primary)"),
    (c3, "CRITICAL ALERTS",   str(n_critical),       "var(--danger)"),
    (c4, "L2 ESCALATIONS",    str(n_escalated),      "var(--text-primary)"),
    (c5, "ACTIVE CAMPAIGNS",  str(n_campaigns),      "var(--text-primary)"),
    (c6, "MALICIOUS SOURCES", str(n_ti_bad),         "var(--text-primary)"),
]:
    col.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value" style="color:{color};">{value}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_overview, tab_alerts, tab_campaigns, tab_mitre, tab_ti, tab_soar, tab_eval, tab_feedback = st.tabs([
    "Executive Overview", "Alert Investigation", "Campaign Analysis",
    "MITRE ATT&CK", "Threat Intelligence", "SOAR Automation", "Quality Evaluation",
    "Feedback Calibration",
])


with tab_overview:
    st.markdown("### Security Operations Dashboard")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Alert Severity Distribution")
        sev_counts = df_full[df_full["is_alert"]]["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        if not sev_counts.empty:
            color_map = {k: SEVERITY_CONFIG.get(k, {}).get("color", "#3b82f6")
                         for k in sev_counts["Severity"].unique()}
            fig = px.pie(sev_counts, values="Count", names="Severity",
                         color="Severity", color_discrete_map=color_map, hole=0.4)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                              font_color='#94a3b8', height=380)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alerts to display")

    with col2:
        st.markdown("#### Top Attack Classifications")
        type_counts = df_full[df_full["is_alert"]]["alert_type"].value_counts().head(10).reset_index()
        type_counts.columns = ["Attack Type", "Count"]
        if not type_counts.empty:
            fig = px.bar(type_counts, x="Count", y="Attack Type", orientation="h",
                         color="Count", color_continuous_scale=["#3b82f6", "#ef4444"])
            fig.update_coloraxes(showscale=False)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                              font_color='#94a3b8', height=380)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No classification data")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    col3, col4 = st.columns(2)

    with col3:
        st.markdown("#### Alert Timeline")
        if not df_alerts.empty:
            try:
                df_alerts2 = df_alerts.copy()
                df_alerts2["ts_dt"] = pd.to_datetime(df_alerts2["timestamp"], errors="coerce")
                df_alerts2 = df_alerts2.dropna(subset=["ts_dt"])
                if not df_alerts2.empty:
                    ts = df_alerts2.set_index("ts_dt").resample("1h").size().reset_index()
                    ts.columns = ["Timestamp", "Alert Count"]
                    fig = px.line(ts, x="Timestamp", y="Alert Count", line_shape="spline")
                    fig.update_traces(line_color="#3b82f6", line_width=2)
                    fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                                      font_color='#94a3b8', height=380)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No valid timestamps for timeline")
            except Exception as e:
                st.info(f"Timeline unavailable: {e}")
        else:
            st.info("No alerts for timeline")

    with col4:
        st.markdown("#### Risk Score Distribution")
        risk_data = df_full[df_full["is_alert"] & df_full["risk_score"].notna()]["risk_score"]
        if not risk_data.empty:
            fig = px.histogram(risk_data, nbins=20, color_discrete_sequence=["#3b82f6"],
                               labels={"value": "Risk Score"})
            fig.add_vline(x=70, line_dash="dash", line_color="#ef4444",
                          annotation_text="High Risk Threshold")
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                              font_color='#94a3b8', height=380)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No risk score data")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    col5, col6 = st.columns(2)

    with col5:
        st.markdown("#### Detection Performance")
        tp = alert_sum.get("true_positives", 0)
        fp = alert_sum.get("false_positives", 0)
        total_classified = tp + fp
        if total_classified > 0:
            precision = tp / total_classified * 100
            st.metric("Precision", f"{precision:.1f}%", help="TP / all alerts raised")
            fn = len(df_full[
                df_full["is_alert"]
                & ~df_full["true_positive"].fillna(False)
                & ~df_full["false_positive"].fillna(False)
            ])
            if fn > 0:
                recall = tp / (tp + fn) * 100
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                st.metric("Recall (est.)", f"{recall:.1f}%")
                st.metric("F1 (est.)", f"{f1:.1f}%")
            st.metric("False Positive Rate", f"{fp/total_classified*100:.1f}%")
        else:
            st.info("No classified alerts yet.")

    with col6:
        st.markdown("#### Source IP Threat Analysis")
        ip_data = df_full[df_full["is_alert"]].groupby("source_ip").agg(
            severity=("severity", lambda x: x.value_counts().index[0] if len(x) > 0 else "LOW"),
            risk_score=("risk_score", "mean"),
            alert_count=("result_id", "count")
        ).reset_index().sort_values("alert_count", ascending=False).head(10)
        if not ip_data.empty:
            fig = px.bar(ip_data, x="alert_count", y="source_ip", orientation="h",
                         color="risk_score", color_continuous_scale=["#22c55e","#f59e0b","#ef4444"])
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                              font_color='#94a3b8', height=380)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No IP data available")


with tab_alerts:
    st.markdown(f"### Alert Investigation Center — *{len(df_alerts)} alerts*")
    if not df_alerts.empty:
        display_cols = ["result_id","severity","alert_type","source_ip","outcome",
                        "fp_score","risk_score","confidence","escalate","true_positive",
                        "is_campaign","hallucinated","timestamp"]
        avail = [c for c in display_cols if c in df_alerts.columns]
        disp  = df_alerts[avail].copy()
        if "confidence" in disp.columns:
            disp["confidence"] = disp["confidence"].apply(
                lambda x: f"{x:.0%}" if pd.notna(x) and x != "" else "N/A"
            )
        if "timestamp" in disp.columns:
            disp["timestamp"] = disp["timestamp"].apply(format_timestamp)
        disp = disp.rename(columns={
            "result_id":"Alert ID","severity":"Severity","alert_type":"Attack Type",
            "source_ip":"Source IP","outcome":"Outcome","fp_score":"FP Score",
            "risk_score":"Risk Score","confidence":"Confidence","escalate":"Escalate",
            "true_positive":"TP","is_campaign":"Campaign","hallucinated":"Hallucination",
            "timestamp":"Timestamp",
        })
        st.dataframe(disp, use_container_width=True, hide_index=True,
                     column_config={
                         "FP Score":      st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d"),
                         "Risk Score":    st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d"),
                         "Escalate":      st.column_config.CheckboxColumn(width="small"),
                         "TP":            st.column_config.CheckboxColumn(width="small"),
                         "Campaign":      st.column_config.CheckboxColumn(width="small"),
                         "Hallucination": st.column_config.CheckboxColumn(width="small"),
                     })

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown("### Alert Deep Dive")

        alert_ids = df_alerts[df_alerts["result_id"].notna()]["result_id"].tolist()
        if alert_ids:
            sel_id  = st.selectbox("Select Alert ID", options=alert_ids)
            sel_row = df_alerts[df_alerts["result_id"] == sel_id].iloc[0]

            st.markdown(badge(sel_row.get("severity", "")), unsafe_allow_html=True)
            st.markdown("")

            col_l, col_r = st.columns(2)
            with col_l:
                st.markdown(f"**Alert ID:** `{sel_id}`")
                st.markdown(f"**Attack Type:** `{sel_row.get('alert_type','N/A')}`")
                st.markdown(f"**Source IP:** `{sel_row.get('source_ip','N/A')}`")
                st.markdown(f"**Target URL:** `{sel_row.get('target_url','N/A') or 'N/A'}`")
                st.markdown(f"**HTTP Status:** `{sel_row.get('status_code','N/A')}`")
                st.markdown(f"**Outcome:** `{sel_row.get('outcome','N/A')}`")
                fp = int(sel_row.get("fp_score", 50) or 50)
                rs = int(sel_row.get("risk_score", 0) or 0)
                st.markdown(f"**FP Score:** `{fp}/100`")
                st.progress(max(0, min(100, 100 - fp)), text=f"Confidence: {100-fp}%")
                st.markdown(f"**Risk Score:** `{rs}/100`")
                st.progress(max(0, min(100, rs)), text=f"Risk: {rs}%")

            with col_r:
                st.markdown("**Summary:**")
                st.info(sel_row.get("summary", "No summary available") or "No summary available")
                evidence = _safe_list(sel_row.get("evidence"))
                if evidence:
                    st.markdown("**Attack Evidence:**")
                    for ev in evidence:
                        st.markdown(f'<div class="code-block">{ev}</div>', unsafe_allow_html=True)
                actions = _safe_list(sel_row.get("actions"))
                if actions:
                    st.markdown("**Recommended Actions:**")
                    for a in actions:
                        st.markdown(f"- {a}")
                if sel_row.get("escalate"):
                    st.error(f"**ESCALATION REQUIRED — SOC LEVEL 2**\n\n{sel_row.get('esc_reason','')}")
                if sel_row.get("is_campaign"):
                    st.warning(f"**CAMPAIGN DETECTED**\n\n{sel_row.get('corr_summary','')}")
                if sel_row.get("hallucinated"):
                    flags = _safe_list(sel_row.get("h_flags"))
                    st.warning("**LLM HALLUCINATION FLAGS**\n\n" + "\n".join(f"- {f}" for f in flags))

            with st.expander("Raw Alert JSON"):
                orig = next((r for r in raw_data.get("results", []) if r.get("result_id") == sel_id), {})
                st.json(orig.get("alert", {}))
            with st.expander("Raw Log Data"):
                orig = next((r for r in raw_data.get("results", []) if r.get("result_id") == sel_id), {})
                st.json(orig.get("raw_log", {}))
    else:
        st.info("No alerts match current filters.")


with tab_campaigns:
    st.markdown("### Multi-Stage Attack Campaign Analysis")
    campaigns = raw_data.get("campaigns", [])
    if campaigns:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Campaigns",    len(campaigns))
        m2.metric("Confirmed Breaches", sum(1 for c in campaigns if "CONFIRMED_BREACH"      in c.get("campaign_indicators",[])))
        m3.metric("Brute Force",        sum(1 for c in campaigns if "BRUTE_FORCE_CAMPAIGN"  in c.get("campaign_indicators",[])))
        m4.metric("Multi-Vector",       sum(1 for c in campaigns if "MULTI_VECTOR_ATTACK"   in c.get("campaign_indicators",[])))

        for camp in sorted(campaigns, key=lambda x: -x.get("correlation_risk_score", 0)):
            risk = camp.get("correlation_risk_score", 0)
            inds = camp.get("campaign_indicators", [])
            with st.expander(f"Campaign: {camp.get('source_ip','?')} — Risk: {risk}/100 — {len(inds)} indicators"):
                cc1, cc2 = st.columns(2)
                with cc1:
                    st.markdown(f"**Source IP:** `{camp.get('source_ip')}`")
                    st.markdown(f"**Log Count:** `{camp.get('log_count')}`")
                    st.markdown(f"**Attack Vectors:** `{', '.join(camp.get('attack_types',[]))}`")
                    st.markdown(f"**Risk Score:** `{risk}/100`")
                    st.markdown(f"**Successful Requests:** `{camp.get('has_successful_request')}`")
                    st.markdown(f"**Failed Logins:** `{camp.get('failed_login_count',0)}`")
                with cc2:
                    st.markdown("**Indicators:**")
                    for ind in inds:
                        bg = "#7f1d1d" if "BREACH" in ind else "#3d2608" if "EXPLOIT" in ind else "#1e3a5f"
                        st.markdown(
                            f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;'
                            f'font-size:0.7rem;margin:2px;display:inline-block">{ind}</span>',
                            unsafe_allow_html=True,
                        )
                    st.markdown(f"**Summary:**\n{camp.get('correlation_summary','')}")
    else:
        st.info("No correlated campaigns detected.")


with tab_mitre:
    st.markdown("### MITRE ATT&CK Framework Coverage")
    if not df_alerts.empty and df_alerts["mitre_tactic"].notna().any():
        tactic_counts = df_alerts["mitre_tactic"].dropna().value_counts().reset_index()
        tactic_counts.columns = ["Tactic", "Count"]
        fig = px.bar(tactic_counts, x="Tactic", y="Count",
                     color="Count", color_continuous_scale=["#1e3a5f","#3b82f6","#ef4444"])
        fig.update_coloraxes(showscale=False)
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                          font_color='#94a3b8', height=400)
        st.plotly_chart(fig, use_container_width=True)

        tech_df = df_alerts[df_alerts["mitre_tactic"].notna()][[
            "alert_type","mitre_tactic","mitre_tactic_id","mitre_technique","mitre_t_id","severity"
        ]].drop_duplicates().sort_values("mitre_tactic")
        st.dataframe(tech_df, use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE ATT&CK data available.")


with tab_ti:
    st.markdown("### Threat Intelligence Enrichment")
    ti_all = df_full[df_full["ti_reputation"].notna() & (df_full["ti_reputation"] != "")].copy()
    ti_bad = ti_all[ti_all["ti_reputation"].isin(["MALICIOUS","SUSPICIOUS"])].copy()

    t1, t2, t3 = st.columns(3)
    t1.metric("Enriched IPs",  len(ti_all["source_ip"].dropna().unique()))
    t2.metric("Malicious",     len(ti_all[ti_all["ti_reputation"]=="MALICIOUS"]["source_ip"].dropna().unique()))
    t3.metric("Suspicious",    len(ti_all[ti_all["ti_reputation"]=="SUSPICIOUS"]["source_ip"].dropna().unique()))

    if not ti_bad.empty:
        ti_disp = ti_bad.groupby("source_ip").agg(
            reputation=("ti_reputation","first"),
            ti_score=("ti_score","first"),
            alert_count=("is_alert","sum"),
            attack_types=("alert_type", lambda x: ", ".join(sorted(set(x.dropna())))),
        ).reset_index().sort_values("ti_score", ascending=False)
        for _, row in ti_disp.iterrows():
            with st.expander(f"{row['source_ip']} — Score: {row.get('ti_score',0)}/100"):
                st.markdown(f"**Reputation:** {ti_badge(row['reputation'])}", unsafe_allow_html=True)
                st.markdown(f"**Threat Score:** `{row.get('ti_score',0)}/100`")
                st.markdown(f"**Alert Count:** `{int(row.get('alert_count',0))}`")
                st.markdown(f"**Attack Types:** `{row.get('attack_types','N/A')}`")
    else:
        st.info("No malicious/suspicious TI matches. Set ABUSEIPDB_API_KEY for enrichment.")


with tab_soar:
    st.markdown("### SOAR Automation")
    soar_alerts = df_alerts[df_alerts["soar_playbook"].notna() & (df_alerts["soar_playbook"] != "")].copy()
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Playbooks Executed", len(soar_alerts))
    s2.metric("Auto-Escalated",     int(soar_alerts["soar_escalate"].sum())  if not soar_alerts.empty else 0)
    s3.metric("Tickets Created",    int(soar_alerts["soar_ticket"].notna().sum()) if not soar_alerts.empty else 0)
    s4.metric("Avg SLA (min)",      int(soar_alerts["soar_sla"].mean())      if not soar_alerts.empty else 60)

    if not soar_alerts.empty:
        disp = soar_alerts[[
            "soar_ticket","severity","alert_type","source_ip","soar_playbook","soar_escalate","soar_sla"
        ]].rename(columns={
            "soar_ticket":"Ticket","severity":"Priority","alert_type":"Attack Type",
            "source_ip":"Source IP","soar_playbook":"Playbook",
            "soar_escalate":"Auto-Escalate","soar_sla":"SLA (min)",
        })
        st.dataframe(disp, use_container_width=True, hide_index=True)
    else:
        st.info("No SOAR responses recorded.")


with tab_eval:
    st.markdown("### Alert Quality Evaluation")
    tp = alert_sum.get("true_positives", 0)
    fp = alert_sum.get("false_positives", 0)
    total_c = tp + fp
    if total_c > 0:
        precision = tp / total_c * 100
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Precision", f"{precision:.1f}%")
        fn = len(df_full[
            df_full["is_alert"]
            & ~df_full["true_positive"].fillna(False)
            & ~df_full["false_positive"].fillna(False)
        ])
        if fn > 0:
            recall = tp / (tp + fn) * 100
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            c2.metric("Recall (est.)", f"{recall:.1f}%")
            c3.metric("F1 (est.)", f"{f1:.1f}%")
        c4.metric("FP Rate", f"{fp/total_c*100:.1f}%")

    if _engine_dist:
        eng_df = pd.DataFrame([
            {"Engine": k, "Count": v, "Pct": f"{v/_total_logs*100:.1f}%"}
            for k, v in sorted(_engine_dist.items(), key=lambda x: -x[1])
        ])
        fig = px.bar(eng_df, x="Count", y="Engine", orientation="h",
                     color="Engine",
                     color_discrete_map={
                         "RULE_ALERT": "#ef4444", "RULE_CLEAN": "#10b981",
                         "LLM_ONLY":   "#7c3aed", "CLEAN":      "#06b6d4",
                         "NO_ENGINE":  "#64748b",
                     }, text="Pct")
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8', height=max(200, len(_engine_dist) * 50),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)

    h_stats = raw_data.get("statistics", {}).get("hallucination_stats", {})
    if h_stats:
        st.markdown("#### LLM Hallucination Detection")
        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Total Alerts",       h_stats.get("total_alerts", 0))
        h2.metric("Hallucinated",       h_stats.get("hallucinated_alerts", 0))
        h3.metric("Hallucination Rate", f"{h_stats.get('hallucination_rate',0)}%")
        h4.metric("Total Flags",        h_stats.get("total_flags", 0))

    if eval_data:
        st.markdown("#### External Evaluator Scores")
        ev_sum = eval_data.get("summary", {})
        e1, e2, e3, e4 = st.columns(4)
        e1.metric("Avg Quality", f"{ev_sum.get('avg_quality_score',0)}/10")
        e2.metric("Evaluated",   ev_sum.get("alerts_generated", 0))
        e3.metric("True Pos",    ev_sum.get("true_positives", 0))
        e4.metric("False Pos",   ev_sum.get("false_positives", 0))
    else:
        st.info("Point **Evaluation report** to your evaluateur_complet.py output for detailed scores.")


with tab_feedback:
    st.markdown("### Analyst Feedback Calibration")
    st.markdown("*Override AI classifications to calibrate false positive detection accuracy*")

    # Attempt to load the optional feedback_loop module
    try:
        _pipeline_dir = os.path.dirname(os.path.abspath(__file__))
        if _pipeline_dir not in sys.path:
            sys.path.insert(0, _pipeline_dir)
        from feedback_loop import get_feedback_loop
        fb = get_feedback_loop()
        fb_available = True
    except Exception:
        fb_available = False

    if fb_available:
        fb_stats = fb.get_stats()

        f1, f2, f3, f4 = st.columns(4)
        f1.metric("Total Analyst Feedback",  fb_stats.get("total_feedback", 0))
        f2.metric("Confirmed True Positives", fb_stats.get("analyst_tps", 0))
        f3.metric("Confirmed False Positives",fb_stats.get("analyst_fps", 0))
        f4.metric("Uncertain Verdicts",       fb_stats.get("analyst_uncertain", 0))

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        st.markdown("#### Submit Analyst Verdict")

        feedback_alert_ids = df_alerts[df_alerts["result_id"].notna()]["result_id"].tolist()
        if feedback_alert_ids:
            fb_col1, fb_col2 = st.columns(2)
            with fb_col1:
                fb_id      = st.selectbox("Alert ID for Review", options=feedback_alert_ids, key="fb_sel")
                fb_verdict = st.radio(
                    "Verdict Classification",
                    ["TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN"],
                    horizontal=True, key="fb_verdict",
                )
            with fb_col2:
                fb_note = st.text_area(
                    "Analyst Notes", key="fb_note", height=100,
                    placeholder="Provide context for this classification…",
                )
                if st.button("Submit Verdict", key="fb_submit", use_container_width=True):
                    sel   = df_alerts[df_alerts["result_id"] == fb_id]
                    atype = sel.iloc[0].get("alert_type", "Unknown") if not sel.empty else "Unknown"
                    fb.record_feedback(fb_id, atype, fb_verdict, fb_note)
                    st.success(f"Verdict recorded: {fb_id} → {fb_verdict}")
                    st.rerun()
        else:
            st.info("No alerts available for review with current filters.")

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Calibration adjustments table
        adjustments = fb_stats.get("calibration_adjustments", {})
        if adjustments:
            st.markdown("#### FP Score Calibration Adjustments")
            adj_df = pd.DataFrame([
                {"Attack Classification": k, "FP Score Adjustment": f"{v:+.1f}"}
                for k, v in adjustments.items()
            ])
            st.dataframe(adj_df, use_container_width=True, hide_index=True)

        # Feedback history
        all_fb = fb.get_all_feedback()
        if all_fb:
            st.markdown("#### Feedback History")
            fb_df = pd.DataFrame(all_fb)
            fb_df = fb_df[["result_id", "alert_type", "analyst_verdict", "analyst_note", "recorded_at"]]
            fb_df = fb_df.rename(columns={
                "result_id":       "Alert ID",
                "alert_type":      "Attack Type",
                "analyst_verdict": "Verdict",
                "analyst_note":    "Analyst Notes",
                "recorded_at":     "Timestamp",
            })
            st.dataframe(
                fb_df.sort_values("Timestamp", ascending=False).head(50),
                use_container_width=True,
                hide_index=True,
            )
    else:
        st.markdown(
            '<div class="status-warning">Feedback calibration module unavailable. '
            'Ensure <code>feedback_loop.py</code> is present in the working directory.</div>',
            unsafe_allow_html=True,
        )


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="enterprise-footer">
    SOC AI Analyst Platform v5.1 — Fast LLM + Rule Engine |
    Processing: {raw_data.get("statistics",{}).get("duration_sec","N/A")}s |
    LLM: {"Online ✓" if _ollama_online else "Offline ✗"} |
    Mode: {raw_data.get("metadata",{}).get("version","N/A")} |
    Last refresh: {datetime.now().strftime('%H:%M:%S')}
</div>
""", unsafe_allow_html=True)