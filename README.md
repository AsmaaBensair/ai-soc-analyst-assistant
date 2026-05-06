# 🛡️ AI SOC Analyst Assistant — v2.0 (Production)

A hybrid rule engine + LLM pipeline that reads **raw security logs** and
generates structured threat alerts, scored by an automatic evaluator, and
visualized in a professional Streamlit dashboard.

---

## Architecture

```
data/logs.json  (raw syslog / HTTP access / unknown logs)
        │
        ▼
log_parser.py          ← normalize logs, detect attack patterns, compute FP hint
        │
        ▼
main.py  (Hybrid Engine)
  ├─ Rule Engine        ← fast deterministic detection (XSS, SQLi, BruteForce…)
  └─ LLM (llama3)       ← fallback for complex/ambiguous logs
        │
        ▼
hallucination_guard.py ← validate IPs/URLs/users against source log
        │
        ▼
data/results_docker.json
        │
   ┌────┴────────────────┐
   ▼                     ▼
evaluateur_complet.py   dashboard_soc.py  (Streamlit)
data/evaluation_report.json
```

---

## File Summary

| File | Role |
|------|------|
| `log_parser.py` | Normalize raw logs, detect patterns, compute FP/TP hints |
| `prompts.py` | LLM system prompts with strict grounding rules |
| `chain.py` | LangChain + Ollama LLM chain builder |
| `hallucination_guard.py` | Validate generated alerts against source logs |
| `main.py` | Pipeline orchestrator (rule engine + LLM) |
| `evaluateur_complet.py` | Score alert quality on 10 dimensions |
| `dashboard_soc.py` | Streamlit professional dashboard |
| `docker-compose.yml` | Full containerized stack |
| `requirements.txt` | Python dependencies |
| `data/logs.json` | Input raw logs |

---

## Quick Start (Local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Ollama and pull the model
ollama serve &
ollama pull llama3

# 3. Run the pipeline (rule engine + LLM)
python main.py --input data/logs.json --output data/results_docker.json

# 4. Run without LLM (rule engine only — fast, no Ollama needed)
python main.py --input data/logs.json --output data/results_docker.json --no-llm

# 5. Evaluate alert quality
python evaluateur_complet.py --input data/results_docker.json --output data/evaluation_report.json

# 6. Launch the dashboard
streamlit run dashboard_soc.py
# → open http://localhost:8501
```

---

## Quick Start (Docker)

```bash
# Full stack (Ollama + pipeline + evaluator + dashboard)
docker-compose up

# Dashboard only (if results already exist)
docker-compose up soc_dashboard

# Open dashboard: http://localhost:8501
```

---

## CLI Options

### main.py
```
--input    Path to raw logs JSON     (default: data/logs.json)
--output   Path to results JSON      (default: data/results_docker.json)
--limit    Max logs to process       (default: all)
--skip-fp  Skip obvious FPs pre-LLM  (faster)
--no-llm   Rule engine only          (no Ollama needed)
```

### evaluateur_complet.py
```
--input    Path to pipeline results JSON
--output   Path to evaluation report JSON
```

---

## Scoring Dimensions (Evaluator)

| Dimension | Weight | Description |
|-----------|--------|-------------|
| alert_generated | 2.0 | Was an alert raised with evidence? |
| correct_alert_type | 2.0 | Correct attack category named? |
| correct_severity | 1.5 | Severity calibrated to evidence? |
| tp_fp_correct | 2.0 | TP/FP consistent with FP score? |
| fp_score_reasonable | 1.0 | FP score in 0–100 range? |
| mitre_present | 0.5 | MITRE tactic/technique provided? |
| summary_grounded | 1.0 | Summary references real log values? |
| no_hallucination | 1.5 | No invented IPs/users/URLs? |
| recommended_actions | 0.5 | ≥3 specific remediation actions? |
| escalation_correct | 0.5 | Escalation decision justified? |
| **Max** | **12.5** | Normalized to /10 |

---

## False Positive Score (0–100)

| Range | Classification |
|-------|---------------|
| 0–30 | Confirmed True Positive |
| 31–60 | Uncertain — analyst review |
| 61–80 | Likely False Positive |
| 81–100 | Confirmed False Positive |

---

## Anti-Hallucination Layers

| Layer | Where | What it checks |
|-------|-------|---------------|
| Prompt grounding | prompts.py | "Only reference values in the log" |
| Pre-analysis hints | log_parser.py | Annotates null fields, pre-flags TP/FP |
| Post-generation validation | hallucination_guard.py | IP/URL/user must appear in raw log |
| FP logic check | hallucination_guard.py | HTTP 403 ≠ True Positive |
| Temperature=0 | chain.py | Deterministic LLM output |

---

## Bug Fixes vs Original (v1.0)

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| `'str' object has no attribute 'get'` | `process_log()` passed a raw dict to rules then formatted it to string — LLM path received a string | `main.py` now passes the normalized dict to rules and the formatted string to LLM separately |
| Dashboard crashed | `normalize_results()` read wrong keys (`analysis`, `alert_id`) | Rewritten to read v2.0 schema (`alert`, `result_id`, etc.) |
| Evaluator couldn't ground summaries | `result.get("raw_log")` was never stored | `main.py` now stores `raw_log` in every result |
| Rule alerts missing MITRE, TP/FP fields | Rule engine returned minimal dicts | Rule engine now returns full alert schema with MITRE, TP/FP, escalation |
| LLM called even for obvious FPs | No pre-filtering | Added `LIKELY_FP` pre-assessment skip |
| Plotly charts broken | Wrong column names | All charts rebuilt with correct DataFrame columns |
| Missing Streamlit/Plotly in requirements | Only langchain listed | Full requirements.txt with all deps |

---

*SOC Assistant v2.0 — Production Grade | May 2026*
