"""
main.py — SOC Assistant Pipeline Orchestrator v3.0
Flow: logs.json → log_parser → [rule_engine | LLM] → TI enrichment → SOAR → hallucination_guard → results.json
"""

import json
import time
import argparse
import re
from datetime import datetime, timezone

from log_parser import load_logs, format_log_for_llm, is_internal_ip
from chain import build_chain, analyze_log, test_ollama_connection
from hallucination_guard import validate_alert, validate_fp_classification, summarize_hallucinations
from rag_engine import get_rag_engine
from threat_intel import get_ti_engine
from soar_engine import get_soar_engine

_alert_counter = 0

def _next_alert_id() -> str:
    global _alert_counter
    _alert_counter += 1
    return f"GEN-{_alert_counter:04d}"


RULE_MITRE = {
    "Brute Force":         {"mitre_tactic": "Credential Access",      "mitre_tactic_id": "TA0006", "mitre_technique": "Brute Force",                              "mitre_technique_id": "T1110"},
    "XSS":                 {"mitre_tactic": "Initial Access",          "mitre_tactic_id": "TA0001", "mitre_technique": "Exploit Public-Facing Application",        "mitre_technique_id": "T1190"},
    "SQL Injection":       {"mitre_tactic": "Initial Access",          "mitre_tactic_id": "TA0001", "mitre_technique": "Exploit Public-Facing Application",        "mitre_technique_id": "T1190"},
    "Path Traversal":      {"mitre_tactic": "Initial Access",          "mitre_tactic_id": "TA0001", "mitre_technique": "Exploit Public-Facing Application",        "mitre_technique_id": "T1190"},
    "Command Injection":   {"mitre_tactic": "Execution",               "mitre_tactic_id": "TA0002", "mitre_technique": "Command and Scripting Interpreter",        "mitre_technique_id": "T1059"},
    "Privilege Escalation":{"mitre_tactic": "Privilege Escalation",    "mitre_tactic_id": "TA0004", "mitre_technique": "Abuse Elevation Control Mechanism",        "mitre_technique_id": "T1548"},
    "Defense Evasion":     {"mitre_tactic": "Defense Evasion",         "mitre_tactic_id": "TA0005", "mitre_technique": "Indicator Removal",                        "mitre_technique_id": "T1070"},
    "Malicious Scan":      {"mitre_tactic": "Discovery",               "mitre_tactic_id": "TA0007", "mitre_technique": "Network Service Discovery",               "mitre_technique_id": "T1046"},
    "Webshell":            {"mitre_tactic": "Persistence",             "mitre_tactic_id": "TA0003", "mitre_technique": "Server Software Component: Web Shell",    "mitre_technique_id": "T1505.003"},
}


def _compute_risk_score(alert_type: str, fp_score: int, outcome: str, correlation: dict) -> int:
    """Unified risk score 0-100 combining FP score, outcome, and correlation."""
    base = 100 - fp_score
    if outcome == "success":
        base = min(100, base + 20)
    elif outcome == "failure":
        base = max(0, base - 10)
    corr_risk = correlation.get("correlation_risk_score", 0)
    combined = int((base * 0.6) + (corr_risk * 0.4))
    return min(100, combined)


def detect_with_rules(norm_log: dict) -> dict | None:
    message = (norm_log.get("message") or "").lower()
    url     = (norm_log.get("url") or "").lower()
    ua      = (norm_log.get("user_agent") or "").lower()
    status  = str(norm_log.get("status_code") or "")
    src_ip  = norm_log.get("source_ip")
    host    = norm_log.get("target_host")

    alert_type = None
    severity   = "MEDIUM"
    evidence   = []
    outcome    = "unknown"
    fp_score   = 50

    # ── Detection rules ──────────────────────────────────────
    if re.search(r"<script|alert\s*\(|onerror\s*=", url):
        alert_type = "XSS"
        severity   = "CRITICAL" if status == "200" else "HIGH"
        outcome    = "success" if status == "200" else "failure"
        evidence   = [url[:200]]
        fp_score  -= 30

    elif re.search(r"union\s+select|or\s+1=1|information_schema|drop\s+table", url):
        alert_type = "SQL Injection"
        severity   = "CRITICAL" if status == "200" else "HIGH"
        outcome    = "success" if status == "200" else "failure"
        evidence   = [url[:200]]
        fp_score  -= 30

    elif re.search(r"\.\./|/etc/passwd|/etc/shadow|/var/log", url):
        alert_type = "Path Traversal"
        severity   = "CRITICAL" if status == "200" else "HIGH"
        outcome    = "success" if status == "200" else "blocked"
        evidence   = [url[:200]]
        fp_score  -= 30

    elif re.search(r"(cmd|exec|system|execute)\s*=|\|\s*(id|whoami)|/dev/tcp/", url + message):
        alert_type = "Command Injection"
        severity   = "CRITICAL" if status == "200" else "HIGH"
        outcome    = "success" if status == "200" else "unknown"
        evidence   = [url[:200] or message[:200]]
        fp_score  -= 35

    elif re.search(r"webshell|shell\.php\?cmd=", url + message):
        alert_type = "Webshell"
        severity   = "CRITICAL"
        outcome    = "success" if status == "200" else "unknown"
        evidence   = [url[:200]]
        fp_score  -= 40

    elif re.search(r"sqlmap|masscan|nmap|nikto|wpscan|nuclei|zgrab|burp suite|burpsuite", ua):
        alert_type = "Malicious Scan"
        severity   = "HIGH"
        outcome    = "unknown"
        evidence   = [ua[:200]]
        fp_score  -= 25

    elif "failed password" in message:
        alert_type = "Brute Force"
        severity   = "HIGH"
        outcome    = "failure"
        evidence   = [message[:200]]
        fp_score  -= 20

    elif re.search(r"sudo\s*:", message) and "root" in message.lower():
        alert_type = "Privilege Escalation"
        severity   = "HIGH"
        outcome    = "success" if "success=yes" in message else "unknown"
        evidence   = [message[:200]]
        fp_score  -= 25

    elif re.search(r"find.*-delete|rm\s+-rf.*log|log.*delete", message):
        alert_type = "Defense Evasion"
        severity   = "HIGH"
        outcome    = "unknown"
        evidence   = [message[:200]]
        fp_score  -= 25

    if not alert_type:
        return None

    # ── FP modifiers ──────────────────────────────────────────
    if is_internal_ip(src_ip):
        fp_score += 30
    if re.search(r"mozilla|chrome|safari|firefox", ua):
        fp_score += 15
    if status.startswith("4") or status.startswith("3"):
        fp_score += 20

    fp_score = max(0, min(100, fp_score))

    # Correlation boost
    corr = norm_log.get("_correlation", {})
    if corr.get("is_campaign"):
        fp_score = max(0, fp_score - 15)
        if severity == "MEDIUM":
            severity = "HIGH"
        if severity == "HIGH" and corr.get("campaign_indicators"):
            if "CONFIRMED_BREACH" in corr.get("campaign_indicators", []):
                severity = "CRITICAL"

    fp_score = max(0, min(100, fp_score))

    is_tp = fp_score <= 30
    is_fp = fp_score >= 60
    if fp_score > 70:
        severity = "LOW"
    elif fp_score > 50 and severity == "HIGH":
        severity = "MEDIUM"

    escalate = (severity in ("CRITICAL", "HIGH") and outcome == "success") or \
               "CONFIRMED_BREACH" in corr.get("campaign_indicators", [])

    mitre = RULE_MITRE.get(alert_type, {})
    risk_score = _compute_risk_score(alert_type, fp_score, outcome, corr)

    return {
        "is_alert": True,
        "alert_type": alert_type,
        "severity": severity,
        "false_positive_score": fp_score,
        "false_positive_reason": f"Rule-based scoring: {fp_score}/100",
        "true_positive": is_tp,
        "false_positive": is_fp,
        "confidence": round(1 - (fp_score / 100), 2),
        "source_ip": src_ip,
        "target_host": host,
        "target_url": norm_log.get("url"),
        "user": norm_log.get("user"),
        "process": norm_log.get("process"),
        "user_agent": norm_log.get("user_agent"),
        "status_code": status or None,
        "attack_evidence": evidence,
        "outcome": outcome,
        "risk_score": risk_score,
        "summary": f"{alert_type} detected from {src_ip}. Status={status}. FP={fp_score}/100. Risk={risk_score}/100.",
        "recommended_actions": [
            f"Block {src_ip} at firewall if attack is confirmed",
            f"Review logs for {host or 'target host'} around the event timestamp",
            "Enable enhanced logging and alert correlation for this source",
        ],
        "escalate_to_soc_level2": escalate,
        "escalation_reason": ("High-confidence attack with successful outcome" if escalate
                              else "Alert does not meet L2 escalation threshold"),
        **mitre,
    }


def process_log(norm_log: dict, chain, index: int, rag_engine=None,
                ti_engine=None, soar_engine=None) -> dict:
    start = time.time()
    raw_log = norm_log.get("raw_log", {})
    corr = norm_log.get("_correlation", {})

    # 1. TI enrichment
    ti_result = {}
    if ti_engine:
        ip = norm_log.get("source_ip")
        if ip and not is_internal_ip(ip):
            ti_result = ti_engine.enrich_ip(ip)

    # 2. Rule engine
    rule_alert = detect_with_rules(norm_log)

    if rule_alert:
        alert = validate_alert(raw_log, rule_alert)
        alert = validate_fp_classification(raw_log, alert)
        if ti_result:
            alert["threat_intel"] = ti_result
            if ti_result.get("reputation") == "MALICIOUS":
                alert["false_positive_score"] = max(0, alert["false_positive_score"] - 20)
                alert["true_positive"] = True
        # SOAR response
        if soar_engine:
            alert["soar_response"] = soar_engine.generate_soar_response(alert, corr)
        if rag_engine:
            rag_engine.add_alert(str(norm_log), alert)
        return _build_result(norm_log, alert, index, start, "RULE_MATCH", ti_result, corr)

    # 3. Skip obvious FP
    fp_hint = norm_log.get("fp_hint", {})
    if fp_hint.get("pre_assessment") == "LIKELY_FP" and not norm_log.get("attack_hints"):
        no_alert = {
            "is_alert": False,
            "false_positive_score": fp_hint.get("fp_score_hint", 80),
            "false_positive_reason": "Pre-assessment LIKELY_FP — skipped LLM",
            "summary": "Benign traffic.",
        }
        return _build_result(norm_log, no_alert, index, start, "SKIPPED_FP", ti_result, corr)

    # 4. RAG + LLM
    log_str = format_log_for_llm(norm_log, index)
    if rag_engine:
        ctx = rag_engine.retrieve(log_str)
        if ctx:
            log_str = ctx + "\n" + log_str

    if not chain:
        no_alert = {"is_alert": False, "summary": "No rule match and no LLM available"}
        return _build_result(norm_log, no_alert, index, start, "RULE_ONLY_NO_ALERT", ti_result, corr)

    try:
        alert = analyze_log(log_str, chain)
    except Exception as e:
        alert = {"is_alert": False, "error": str(e)}

    if isinstance(alert, dict) and alert.get("is_alert"):
        alert = validate_alert(raw_log, alert)
        alert = validate_fp_classification(raw_log, alert)
        if ti_result:
            alert["threat_intel"] = ti_result
        if soar_engine:
            alert["soar_response"] = soar_engine.generate_soar_response(alert, corr)
        if rag_engine:
            rag_engine.add_alert(log_str, alert)
        engine_status = "LLM+RAG"
    else:
        engine_status = "LLM_NO_ALERT"

    return _build_result(norm_log, alert, index, start, engine_status, ti_result, corr)


def _build_result(norm_log, alert, index, start, status, ti_result=None, corr=None) -> dict:
    is_alert = isinstance(alert, dict) and alert.get("is_alert", False)
    return {
        "result_id":          _next_alert_id() if is_alert else None,
        "log_index":          index,
        "log_type":           norm_log.get("log_type", "unknown"),
        "source_ip":          norm_log.get("source_ip"),
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "processing_time_ms": round((time.time() - start) * 1000),
        "status":             status,
        "raw_log":            norm_log.get("raw_log", {}),
        "correlation":        corr or {},
        "threat_intel":       ti_result or {},
        "alert":              alert if isinstance(alert, dict) else {"is_alert": False},
    }


def run(input_file: str, output_file: str, limit=None, skip_fp=False, use_llm=True):
    print("=" * 65)
    print("  SOC ASSISTANT v3.0 — HYBRID PIPELINE")
    print("  Rules + LLM + TI + Correlation + SOAR")
    print("=" * 65)

    print(f"\n[1/5] Loading logs: {input_file}")
    norm_logs = load_logs(input_file)
    if limit:
        norm_logs = norm_logs[:limit]
    print(f"      {len(norm_logs)} logs loaded & correlated")

    chain = None
    if use_llm:
        print("\n[2/5] Connecting to Ollama LLM...")
        if test_ollama_connection():
            chain = build_chain()
            print("      LLM chain ready")
        else:
            print("      [WARN] LLM unavailable — rule engine only")

    print("\n[3/5] Initializing engines...")
    rag_engine  = get_rag_engine() if use_llm else None
    ti_engine   = get_ti_engine()
    soar_engine = get_soar_engine()
    print("      TI engine, SOAR engine ready")

    print(f"\n[4/5] Analyzing {len(norm_logs)} logs...")
    results = []
    start_total = time.time()

    for i, norm_log in enumerate(norm_logs):
        tag = norm_log.get("log_type", "?")
        corr_flag = "🔗" if norm_log.get("_correlation", {}).get("is_campaign") else "  "
        print(f"  [{i+1:>3}/{len(norm_logs)}] {tag:<8} {corr_flag}", end=" ", flush=True)

        result = process_log(norm_log, chain, i, rag_engine, ti_engine, soar_engine)
        results.append(result)
        is_alert = result["alert"].get("is_alert")
        sev = result["alert"].get("severity", "")
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
        print(f"{sev_icon} {result['alert'].get('alert_type', 'CLEAN')[:30]}")

    alerts    = [r for r in results if r["alert"].get("is_alert")]
    tps       = [r for r in alerts  if r["alert"].get("true_positive")]
    fps       = [r for r in alerts  if r["alert"].get("false_positive")]
    escalated = [r for r in alerts  if r["alert"].get("escalate_to_soc_level2")]
    sev_dist  = {}
    type_dist = {}
    for r in alerts:
        s = r["alert"].get("severity", "UNKNOWN")
        t = r["alert"].get("alert_type", "Unknown")
        sev_dist[s]  = sev_dist.get(s, 0) + 1
        type_dist[t] = type_dist.get(t, 0) + 1

    halluc_summary = summarize_hallucinations(results)

    # Campaign summary
    campaigns = {}
    for r in results:
        corr = r.get("correlation", {})
        if corr.get("is_campaign"):
            ip = corr.get("source_ip", "unknown")
            campaigns[ip] = corr

    output = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_file":   input_file,
            "version":      "3.0",
            "mode":         "HYBRID SOC (RULES + LLM + TI + SOAR)" if chain else "RULE+TI+SOAR ONLY",
        },
        "statistics": {
            "total_logs_analyzed":   len(results),
            "alert_summary": {
                "alerts_generated": len(alerts),
                "true_positives":   len(tps),
                "false_positives":  len(fps),
                "escalated":        len(escalated),
                "no_alert":         len(results) - len(alerts),
            },
            "severity_distribution":    sev_dist,
            "attack_type_distribution": type_dist,
            "hallucination_stats":      halluc_summary,
            "campaign_count":           len(campaigns),
            "duration_sec":             round(time.time() - start_total, 2),
        },
        "campaigns": list(campaigns.values()),
        "results": results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n[5/5] Results written to: {output_file}")
    print(f"\n{'─'*50}")
    print(f"  Logs analyzed    : {len(results)}")
    print(f"  Alerts generated : {len(alerts)}")
    print(f"  True Positives   : {len(tps)}")
    print(f"  False Positives  : {len(fps)}")
    print(f"  Escalated L2     : {len(escalated)}")
    print(f"  Campaigns Found  : {len(campaigns)}")
    print(f"  Duration         : {round(time.time() - start_total, 2)}s")
    print(f"{'─'*50}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Assistant v3.0 — Hybrid Log Analysis Pipeline")
    parser.add_argument("--input",   default="data/logs.json",           help="Input raw logs JSON")
    parser.add_argument("--output",  default="data/results_docker.json", help="Output results JSON")
    parser.add_argument("--limit",   type=int,                           help="Max logs to process")
    parser.add_argument("--no-llm",  action="store_true",                help="Rule engine only")
    args = parser.parse_args()
    run(input_file=args.input, output_file=args.output,
        limit=args.limit, use_llm=not args.no_llm)
