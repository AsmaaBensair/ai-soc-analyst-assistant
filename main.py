import json
import time
import argparse
import re
from datetime import datetime, timezone
from typing import Optional

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
    "Brute Force":          {"mitre_tactic": "Credential Access",    "mitre_tactic_id": "TA0006",
                             "mitre_technique": "Brute Force",                                "mitre_technique_id": "T1110"},
    "XSS":                  {"mitre_tactic": "Initial Access",        "mitre_tactic_id": "TA0001",
                             "mitre_technique": "Exploit Public-Facing Application",          "mitre_technique_id": "T1190"},
    "SQL Injection":        {"mitre_tactic": "Initial Access",        "mitre_tactic_id": "TA0001",
                             "mitre_technique": "Exploit Public-Facing Application",          "mitre_technique_id": "T1190"},
    "Path Traversal":       {"mitre_tactic": "Initial Access",        "mitre_tactic_id": "TA0001",
                             "mitre_technique": "Exploit Public-Facing Application",          "mitre_technique_id": "T1190"},
    "Command Injection":    {"mitre_tactic": "Execution",             "mitre_tactic_id": "TA0002",
                             "mitre_technique": "Command and Scripting Interpreter",          "mitre_technique_id": "T1059"},
    "Privilege Escalation": {"mitre_tactic": "Privilege Escalation",  "mitre_tactic_id": "TA0004",
                             "mitre_technique": "Abuse Elevation Control Mechanism",          "mitre_technique_id": "T1548"},
    "Defense Evasion":      {"mitre_tactic": "Defense Evasion",       "mitre_tactic_id": "TA0005",
                             "mitre_technique": "Indicator Removal",                          "mitre_technique_id": "T1070"},
    "Malicious Scan":       {"mitre_tactic": "Discovery",             "mitre_tactic_id": "TA0007",
                             "mitre_technique": "Network Service Discovery",                  "mitre_technique_id": "T1046"},
    "Webshell":             {"mitre_tactic": "Persistence",           "mitre_tactic_id": "TA0003",
                             "mitre_technique": "Server Software Component: Web Shell",       "mitre_technique_id": "T1505.003"},
}




def _compute_risk_pre_score(norm_log: dict) -> int:
    url     = (norm_log.get("url")        or "").lower()
    ua      = (norm_log.get("user_agent") or "").lower()
    message = (norm_log.get("message")    or "").lower()
    status  = str(norm_log.get("status_code") or "")
    src_ip  = norm_log.get("source_ip") or ""

    score = 20  # baseline

    if re.search(r"/backup|/export|/dump|/download.*db|employee.*export"
                 r"|full[-_]db|all[-_]data|bulk[-_]extract", url):
        score += 50
    if re.search(r"/private|/restricted|/internal|/confidential"
                 r"|/sensitive|/secret", url):
        score += 40
    if re.search(r"union\s+select|or\s+1=1|information_schema|drop\s+table"
                 r"|sleep\s*\(|<script|onerror\s*=|javascript:|\.\.\/|/etc/passwd"
                 r"|/etc/shadow|cmd=|exec=|webshell|shell\.php", url + message):
        score += 55

    OFFENSIVE_TOOLS = [
        "sqlmap", "masscan", "nmap", "nikto", "wpscan", "nuclei", "zgrab",
        "burp", "metasploit", "acunetix", "gobuster", "dirbuster",
    ]
    if any(t in ua for t in OFFENSIVE_TOOLS):
        score += 50

    if src_ip and not is_internal_ip(src_ip):
        if re.search(r"/admin|/manager|/phpmyadmin|/cpanel|/wp-admin"
                     r"|/console|/controlpanel|/backup|/export", url):
            score += 35
        elif re.search(r"/api|/auth|/login", url):
            score += 10

    if status == "200" and re.search(
            r"/backup|/export|/private|/admin|/etc/passwd|webshell"
            r"|\.sql$|\.env$|/config\.", url):
        score += 30

    if re.search(r"failed password|invalid user|authentication failure"
                 r"|account.*disabled.*token|token.*disabled.*account", message):
        score += 25
    if re.search(r"unusual.*geo|geo.*mismatch|impossible travel"
                 r"|session.*anomaly|concurrent.*session", message):
        score += 20
    if re.search(r"auth.*bypass|bypass.*auth|invalid\s+session|session.*invalid"
                 r"|session.*anomaly|broken.*auth", message):
        score += 50
    if re.search(r"token.*refresh.*disabled|disabled.*account.*token"
                 r"|multiple.*token.*refresh|token.*disabled|token.*refresh.*disable", message):
        score += 55
    if re.search(r"remote.*admin.*session|admin.*session.*established"
                 r"|remote.*db.*session|database.*remote.*session"
                 r"|remote.*administrative.*session", message):
        score += 45
    if re.search(r"unusual.*geo|geographic.*region|geo.*mismatch"
                 r"|impossible.*travel|foreign.*ip.*session"
                 r"|unusual.*geographic", message):
        score += 40
    if re.search(r"bulk.*download|bulk.*archive|unexpected.*download"
                 r"|large.*dataset.*export|employee.*export"
                 r"|large.*employee|dataset.*export", message):
        score += 50

    if is_internal_ip(src_ip):
        score -= 15
    if status.startswith("4") or status.startswith("3"):
        score -= 10
    if re.search(r"mozilla|chrome|safari|firefox|gecko", ua):
        score -= 5

    return max(0, min(100, score))



def _extract_risk_indicators(norm_log: dict, risk_pre_score: int) -> list[str]:
    url     = (norm_log.get("url")        or "")
    ua      = (norm_log.get("user_agent") or "").lower()
    message = (norm_log.get("message")    or "")
    status  = str(norm_log.get("status_code") or "")
    src_ip  = norm_log.get("source_ip") or ""
    url_l   = url.lower()
    msg_l   = message.lower()

    bullets = []

    if re.search(r"/backup|/export|/dump|/download.*db|employee.*export"
                 r"|full[-_]db|all[-_]data|bulk[-_]extract", url_l):
        bullets.append(f"Data exfiltration path in URL: {url[:120]}")
    if re.search(r"/private|/restricted|/internal|/confidential"
                 r"|/sensitive|/secret", url_l):
        bullets.append(f"Restricted/private resource in URL: {url[:120]}")

    for pattern, label in [
        (r"union\s+select",     "SQL Injection keyword (UNION SELECT)"),
        (r"or\s+1=1",           "SQL Injection keyword (OR 1=1)"),
        (r"information_schema", "SQL Injection keyword (information_schema)"),
        (r"drop\s+table",       "SQL Injection keyword (DROP TABLE)"),
        (r"sleep\s*\(",         "SQL time-based injection (sleep())"),
        (r"<script",            "XSS payload (<script>)"),
        (r"onerror\s*=",        "XSS payload (onerror=)"),
        (r"javascript:",        "XSS payload (javascript:)"),
        (r"\.\.\/" ,            "Path traversal (../)"),
        (r"/etc/passwd",        "Path traversal target (/etc/passwd)"),
        (r"/etc/shadow",        "Path traversal target (/etc/shadow)"),
        (r"cmd=|exec=",         "Command injection parameter (cmd=/exec=)"),
        (r"webshell|shell\.php","Webshell reference in URL/message"),
    ]:
        if re.search(pattern, url_l + msg_l):
            bullets.append(label)

    for tool in ["sqlmap", "masscan", "nmap", "nikto", "wpscan", "nuclei",
                 "zgrab", "burp", "metasploit", "acunetix", "gobuster", "dirbuster"]:
        if tool in ua:
            bullets.append(f"Offensive security tool in User-Agent: {ua[:80]}")
            break

    if src_ip and not is_internal_ip(src_ip):
        if re.search(r"/admin|/manager|/phpmyadmin|/cpanel|/wp-admin"
                     r"|/console|/controlpanel|/backup|/export", url_l):
            bullets.append(
                f"External IP {src_ip} accessing privileged/sensitive endpoint: {url[:80]}"
            )

    if status == "200" and re.search(
            r"/backup|/export|/private|/admin|/etc/passwd|webshell"
            r"|\.sql|\.env|/config\.", url_l):
        bullets.append(
            f"HTTP 200 (success) on sensitive path — access appears to have succeeded: {url[:80]}"
        )

    if re.search(r"auth.*bypass|bypass.*auth|invalid\s+session|session.*invalid"
                 r"|broken.*auth|session.*anomaly", msg_l):
        bullets.append(
            f"Authentication bypass / invalid session anomaly detected: {message[:120]}"
        )
    if re.search(r"token.*refresh.*disabled|disabled.*account.*token"
                 r"|multiple.*token.*refresh|token.*disabled|token.*refresh.*disable", msg_l):
        bullets.append(
            f"Token activity on disabled/compromised account — possible credential abuse: {message[:120]}"
        )
    if re.search(r"remote.*admin.*session|admin.*session.*established"
                 r"|remote.*db.*session|database.*remote.*session"
                 r"|remote.*administrative.*session", msg_l):
        bullets.append(
            f"Suspicious remote administrative session established: {message[:120]}"
        )
    if re.search(r"unusual.*geo|geographic.*region|geo.*mismatch"
                 r"|impossible.*travel|foreign.*ip.*session"
                 r"|unusual.*geographic", msg_l):
        bullets.append(
            f"Session issued from unusual geographic region — possible account takeover: {message[:120]}"
        )
    if re.search(r"bulk.*download|unexpected.*download|large.*dataset.*export"
                 r"|employee.*export|bulk.*archive|large.*employee", msg_l):
        bullets.append(f"Bulk data access or export detected: {message[:120]}")

    if re.search(r"failed password|invalid user|authentication failure", msg_l):
        bullets.append(f"Authentication failure detected: {message[:100]}")
    if re.search(r"account.*disabled.*token|token.*disabled.*account", msg_l):
        bullets.append(f"Token activity on disabled account: {message[:100]}")
    if re.search(r"unusual.*geo|geo.*mismatch|impossible travel"
                 r"|session.*anomaly|concurrent.*session", msg_l):
        if not any("unusual geographic" in b or "geographic region" in b for b in bullets):
            bullets.append(f"Session/geo anomaly: {message[:100]}")

    if status:
        if status == "200":
            bullets.append("HTTP status: 200 (request succeeded)")
        elif status.startswith("4"):
            bullets.append(f"HTTP status: {status} (request blocked/rejected)")
    if src_ip:
        if is_internal_ip(src_ip):
            bullets.append(f"Source IP is internal: {src_ip}")
        else:
            bullets.append(f"Source IP is external: {src_ip}")

    bullets.append(f"Risk pre-score: {risk_pre_score}/100")
    return bullets



def _compute_fp_score(norm_log: dict, status: str,
                      ti_result: dict, correlation: dict) -> int:
    src_ip = norm_log.get("source_ip") or ""
    ua     = (norm_log.get("user_agent") or "").lower()
    url    = (norm_log.get("url") or "").lower()
    msg    = (norm_log.get("message") or "").lower()

    score = norm_log.get("fp_hint", {}).get("fp_score_hint", 50)

    if status.startswith("4") or status.startswith("3"):
        score += 20
    if is_internal_ip(src_ip):
        score += 30
    if re.search(r"mozilla|chrome|safari|firefox|gecko", ua):
        score += 10

    OFFENSIVE_TOOLS = [
        "sqlmap", "masscan", "nmap", "nikto", "wpscan", "nuclei",
        "zgrab", "burp", "metasploit", "acunetix", "gobuster", "dirbuster",
        "python-requests", "go-http-client", "nmap scripting",
    ]
    if any(t in ua for t in OFFENSIVE_TOOLS):
        score -= 35

    if status == "200":
        SENSITIVE = ["/etc/passwd", "/etc/shadow", "union select",
                     "<script", "webshell", "shell.php", "/dev/tcp",
                     "/backup", "/export", "/private", "/employee/export"]
        if any(p in url + msg for p in SENSITIVE):
            score -= 40
        else:
            score -= 10

    MSG_SUSPICIOUS = [
        "auth bypass", "bypass auth", "invalid session", "session invalid",
        "session anomaly", "broken auth", "token refresh", "disabled account",
        "token disabled", "multiple token", "remote admin", "admin session",
        "remote administrative", "unusual geo", "geographic region",
        "impossible travel", "bulk download", "bulk archive",
        "unexpected download", "large dataset", "employee export",
    ]
    if any(p in msg for p in MSG_SUSPICIOUS):
        score -= 30

    rep = ti_result.get("reputation", "")
    if rep == "MALICIOUS":
        score -= 30
    elif rep == "SUSPICIOUS":
        score -= 15

    indicators = correlation.get("campaign_indicators", [])
    if indicators:
        score -= 15
    if "CONFIRMED_BREACH" in indicators:
        score -= 20
    if "BRUTE_FORCE_CAMPAIGN" in indicators:
        score -= 10
    if "MULTI_VECTOR_ATTACK" in indicators:
        score -= 10

    return max(0, min(100, score))


def _compute_risk_score(fp_score: int, outcome: str,
                        severity: str, correlation: dict) -> int:
    base = 100 - fp_score
    if outcome == "success":
        base = min(100, base + 20)
    elif outcome == "failure":
        base = max(0, base - 10)
    elif outcome == "blocked":
        base = max(0, base - 15)
    sev_bonus = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 0, "LOW": -10}.get(severity, 0)
    base      = min(100, base + sev_bonus)
    corr_risk = correlation.get("correlation_risk_score", 0)
    return min(100, max(0, int(base * 0.65 + corr_risk * 0.35)))




def detect_with_rules(norm_log: dict) -> dict:

    message = (norm_log.get("message") or "").lower()
    url     = (norm_log.get("url") or "").lower()
    ua      = (norm_log.get("user_agent") or "").lower()
    status  = str(norm_log.get("status_code") or "")
    src_ip  = norm_log.get("source_ip") or ""
    method  = (norm_log.get("method") or "").upper()
    log_src = (norm_log.get("log_type") or "").lower()


    if re.search(r"<script|alert\s*\(|onerror\s*=|javascript:", url):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "XSS",
                "evidence":        [norm_log.get("url", "")[:300]],
                "outcome_hint":    "success" if status == "200" else "failure",
                "rule_matched":    "XSS pattern in URL",
                "rule_confidence": 0.85,
            }
        }

    if re.search(r"union\s+select|or\s+1=1|information_schema|drop\s+table|sleep\s*\(", url):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "SQL Injection",
                "evidence":        [norm_log.get("url", "")[:300]],
                "outcome_hint":    "success" if status == "200" else "failure",
                "rule_matched":    "SQLi pattern in URL",
                "rule_confidence": 0.90,
            }
        }

    if re.search(r"\.\.\/|/etc/passwd|/etc/shadow|/var/log", url):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Path Traversal",
                "evidence":        [norm_log.get("url", "")[:300]],
                "outcome_hint":    "success" if status == "200" else "blocked",
                "rule_matched":    "LFI pattern in URL",
                "rule_confidence": 0.88,
            }
        }

    if re.search(r"(cmd|exec|system|execute)\s*=|\|\s*(id|whoami|cat)|/dev/tcp/|bash\s+-i",
                 url + message):
        raw = norm_log.get("url") or norm_log.get("message") or ""
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Command Injection",
                "evidence":        [raw[:300]],
                "outcome_hint":    "success" if status == "200" else "unknown",
                "rule_matched":    "RCE/cmd pattern in URL or message",
                "rule_confidence": 0.87,
            }
        }

    if re.search(r"webshell|shell\.php\?cmd=|\.php\?cmd=", url + message):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Webshell",
                "evidence":        [norm_log.get("url", "")[:300]],
                "outcome_hint":    "success" if status == "200" else "unknown",
                "rule_matched":    "Webshell pattern in URL",
                "rule_confidence": 0.92,
            }
        }

    if re.search(r"sqlmap|masscan|nmap|nikto|wpscan|nuclei|zgrab|burp\s*suite|burpsuite"
                 r"|dirbuster|gobuster", ua):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Malicious Scan",
                "evidence":        [norm_log.get("user_agent", "")[:300]],
                "outcome_hint":    "unknown",
                "rule_matched":    "Malicious tool in User-Agent",
                "rule_confidence": 0.95,
            }
        }

    if "failed password" in message or "invalid user" in message:
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Brute Force",
                "evidence":        [(norm_log.get("message") or "")[:300]],
                "outcome_hint":    "failure",
                "rule_matched":    "SSH brute force / user enumeration pattern",
                "rule_confidence": 0.80,
            }
        }

    if re.search(r"sudo\s*:", message) and "root" in message:
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Privilege Escalation",
                "evidence":        [(norm_log.get("message") or "")[:300]],
                "outcome_hint":    "success" if "success=yes" in message else "unknown",
                "rule_matched":    "sudo→root elevation pattern",
                "rule_confidence": 0.82,
            }
        }

    if re.search(r"find.*-delete|rm\s+-rf.*log|log.*delete", message):
        return {
            "decision": "ALERT",
            "hint": {
                "alert_type":      "Defense Evasion",
                "evidence":        [(norm_log.get("message") or "")[:300]],
                "outcome_hint":    "unknown",
                "rule_matched":    "Log deletion / tampering pattern",
                "rule_confidence": 0.78,
            }
        }



    
    if re.search(r"^/health$|^/ping$|^/ready$|^/live$|^/status$|^/metrics$", url) \
            and status in ("200", "204"):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "Health check / monitoring endpoint", "rule_confidence": 0.99}
        }

    
    if re.search(r"\.(ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|css|js|map)(\?|$)", url) \
            and status in ("200", "204", "304", "301", "302"):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "Static asset request", "rule_confidence": 0.97}
        }

  
    if method == "OPTIONS":
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "CORS preflight OPTIONS request", "rule_confidence": 0.98}
        }

    if status in ("301", "302") and not re.search(r"script|exec|cmd|bypass", url + message):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "Normal HTTP redirect (301/302)", "rule_confidence": 0.90}
        }

   
    if status == "404" and is_internal_ip(src_ip) \
            and not re.search(r"/admin|/backup|/export|/private|/config|passwd", url):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "404 from internal IP on non-sensitive path",
                     "rule_confidence": 0.88}
        }

   
    if re.search(r"session\s+opened\s+for\s+user|accepted\s+publickey|accepted\s+password"
                 r"|successful\s+login|authentication\s+success", message) \
            and is_internal_ip(src_ip):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "Normal successful authentication from internal IP",
                     "rule_confidence": 0.85}
        }

    if log_src in ("syslog", "system") \
            and re.search(r"cron\[|systemd\[|kernel:|dbus\[|ntpd\[|rsyslogd"
                          r"|started\s+\w+\.service|reached\s+target", message) \
            and not re.search(r"error|fail|deny|block|attack|exploit", message):
        return {
            "decision": "CLEAN",
            "hint": {"rule_matched": "Normal system/cron/service log entry",
                     "rule_confidence": 0.93}
        }


    return {"decision": None, "hint": None}




def _build_llm_input(norm_log: dict, index: int,
                     risk_pre_score: int,
                     rag_context: str = "") -> str:
    full_log_str = format_log_for_llm(norm_log, index)
    parts = []

    if rag_context:
        parts.append(
            f"=== THREAT INTELLIGENCE CONTEXT ===\n{rag_context}\n"
            f"===================================\n"
        )

    if risk_pre_score >= 25:
        indicators = _extract_risk_indicators(norm_log, risk_pre_score)
        bullets    = "\n".join(f"  • {ind}" for ind in indicators)
        parts.append(
            f"=== SUSPICIOUS INDICATORS FOUND (no rule matched — your analysis is primary) ===\n"
            f"The pre-analysis engine flagged these concrete signals in this log.\n"
            f"You MUST address each one in your reasoning before setting is_alert.\n"
            f"\n"
            f"{bullets}\n"
            f"\n"
            f"If any of the above is a genuine security concern, set is_alert = true.\n"
            f"Only set is_alert = false if you can explain why EACH indicator is benign.\n"
            f"==================================================================================\n"
        )
    else:
        parts.append(
            "=== PRE-ANALYSIS ===\n"
            "No rule matched. Risk pre-score is low. Perform full independent analysis.\n"
            "====================\n"
        )

    parts.append(full_log_str)
    return "\n".join(parts)



def _build_rule_alert(rule_hint: dict, norm_log: dict,
                      fp_score: int, correlation: dict) -> dict:
    """Construit une alert complète depuis une décision ALERT du rule engine."""
    status   = str(norm_log.get("status_code") or "")
    src_ip   = norm_log.get("source_ip", "?")
    host     = norm_log.get("target_host")
    outcome  = rule_hint.get("outcome_hint", "unknown")
    atype    = rule_hint.get("alert_type", "Unknown")

    is_tp = fp_score <= 30
    is_fp = fp_score >= 65

    indicators = correlation.get("campaign_indicators", [])
    final_sev  = ("CRITICAL" if (status == "200" and fp_score < 25) else
                  "HIGH"     if fp_score < 40 else
                  "MEDIUM"   if fp_score < 60 else "LOW")
    if "CONFIRMED_BREACH" in indicators and final_sev in ("MEDIUM", "LOW"):
        final_sev = "HIGH"

    escalate   = (final_sev in ("CRITICAL", "HIGH") and outcome == "success" and is_tp) or \
                 "CONFIRMED_BREACH" in indicators
    mitre      = RULE_MITRE.get(atype, {})
    risk_score = _compute_risk_score(fp_score, outcome, final_sev, correlation)

    return {
        "is_alert":               True,
        "alert_type":             atype,
        "alert_type_source":      "RULE_ALERT",
        "rule_matched":           rule_hint.get("rule_matched", ""),
        "severity":               final_sev,
        "false_positive_score":   fp_score,
        "false_positive_reason":  f"Rule ALERT — FP score: {fp_score}/100 (LLM not consulted)",
        "true_positive":          is_tp,
        "false_positive":         is_fp,
        "confidence":             round(rule_hint.get("rule_confidence", 0.85), 2),
        "source_ip":              norm_log.get("source_ip"),
        "target_host":            host,
        "target_url":             norm_log.get("url"),
        "user":                   norm_log.get("user"),
        "process":                norm_log.get("process"),
        "user_agent":             norm_log.get("user_agent"),
        "status_code":            status or None,
        "attack_evidence":        rule_hint.get("evidence", []),
        "outcome":                outcome,
        "risk_score":             risk_score,
        "summary": (
            f"{atype} from {src_ip}. Status={status}. "
            f"FP={fp_score}/100 Risk={risk_score}/100. "
            f"(Rule ALERT — LLM not consulted)"
        ),
        "recommended_actions": [
            f"Block {src_ip} at WAF/firewall if attack confirmed",
            f"Review logs for {host or 'target host'} around event time",
            "Enable enhanced logging and correlation for this source",
        ],
        "escalate_to_soc_level2": escalate,
        "escalation_reason": (
            "Confirmed attack with successful outcome" if escalate
            else "Does not meet L2 threshold"
        ),
        **mitre,
    }


def _build_rule_clean(rule_hint: dict, fp_score: int) -> dict:
    """Construit un résultat CLEAN depuis une décision CLEAN du rule engine."""
    return {
        "is_alert":              False,
        "false_positive_score":  fp_score,
        "false_positive_reason": (
            f"Rule CLEAN: {rule_hint.get('rule_matched', 'explicit clean pattern')} "
            f"(LLM not consulted, fp={fp_score}/100)"
        ),
        "summary": "Log confirmed benign by rule engine.",
    }


def _apply_fp_to_llm(llm: dict, norm_log: dict,
                     fp_score: int, correlation: dict) -> dict:
    """Applique le FP scoring à une alert LLM-only."""
    outcome    = llm.get("outcome", "unknown")
    severity   = llm.get("severity", "MEDIUM")
    risk_score = _compute_risk_score(fp_score, outcome, severity, correlation)

    llm["false_positive_score"] = fp_score
    llm["true_positive"]        = fp_score <= 30
    llm["false_positive"]       = fp_score >= 65
    llm["risk_score"]           = risk_score
    llm["alert_type_source"]    = "LLM_ONLY"

    if not llm.get("mitre_tactic"):
        atype = llm.get("alert_type", "")
        llm.update(RULE_MITRE.get(atype, {}))

    return llm


def process_log(norm_log: dict, chain, index: int, rag_engine=None,
                ti_engine=None, soar_engine=None) -> dict:

    start = time.time()

    raw_log = norm_log.get("raw_log", {})
    corr    = norm_log.get("_correlation", {})


    ti_result = {}
    if ti_engine:
        ip = norm_log.get("source_ip")
        if ip and not is_internal_ip(ip):
            ti_result = ti_engine.enrich_ip(ip)

   
    rule_result = detect_with_rules(norm_log)
    decision    = rule_result["decision"]   
    rule_hint   = rule_result["hint"]

    alert          = None
    engine_status  = ""
    llm_input      = ""
    risk_pre_score = 0
    status         = str(norm_log.get("status_code") or "")
    fp_score       = _compute_fp_score(norm_log, status, ti_result, corr)

    if decision == "ALERT":
       
        alert         = _build_rule_alert(rule_hint, norm_log, fp_score, corr)
        engine_status = "RULE_ALERT"

    elif decision == "CLEAN":
        
        alert         = _build_rule_clean(rule_hint, fp_score)
        engine_status = "RULE_CLEAN"

    else:
   

        risk_pre_score = _compute_risk_pre_score(norm_log)

        if not chain:
            alert = {
                "is_alert":              False,
                "false_positive_score":  fp_score,
                "false_positive_reason": "LLM unavailable and no rule matched.",
                "summary":               "No analysis possible — LLM offline.",
            }
            engine_status = "NO_ENGINE"

        else:
            rag_context = ""
            if rag_engine:
                log_str_for_rag = format_log_for_llm(norm_log, index)
                rag_context = rag_engine.retrieve(log_str_for_rag) or ""

            llm_input = _build_llm_input(
                norm_log, index,
                risk_pre_score=risk_pre_score,
                rag_context=rag_context,
            )

            try:
                llm_raw = analyze_log(llm_input, chain)
                if isinstance(llm_raw, dict):
                    if llm_raw.get("is_alert"):
                        alert         = _apply_fp_to_llm(llm_raw, norm_log, fp_score, corr)
                        engine_status = "LLM_ONLY"
                    else:
                        llm_conf = float(llm_raw.get("confidence", 0.5))
                        alert = {
                            "is_alert":              False,
                            "false_positive_score":  fp_score,
                            "false_positive_reason": (
                                f"LLM analysed full log with indicator context and found no attack "
                                f"(conf={llm_conf:.0%}, fp={fp_score}/100)."
                            ),
                            "summary": llm_raw.get("summary", "No anomaly detected."),
                        }
                        engine_status = "CLEAN"
                else:
                    alert = {
                        "is_alert":              False,
                        "false_positive_score":  fp_score,
                        "false_positive_reason": "Invalid LLM response format.",
                        "summary":               "No analysis possible — invalid LLM response.",
                    }
                    engine_status = "NO_ENGINE"
            except Exception as e:
                alert = {
                    "is_alert":              False,
                    "false_positive_score":  fp_score,
                    "false_positive_reason": f"LLM error: {e}",
                    "summary":               "No analysis possible — LLM error.",
                }
                engine_status = "NO_ENGINE"

    if isinstance(alert, dict) and alert.get("is_alert"):
        alert = validate_alert(raw_log, alert)
        alert = validate_fp_classification(raw_log, alert)

    if ti_result:
        alert["threat_intel"] = ti_result
        if ti_result.get("reputation") == "MALICIOUS":
            alert["false_positive_score"] = max(0, alert.get("false_positive_score", 50) - 20)
            alert["true_positive"] = True

    if soar_engine:
        alert["soar_response"] = soar_engine.generate_soar_response(alert, corr)

    if rag_engine and llm_input:
        rag_engine.add_alert(llm_input, alert)

    if isinstance(alert, dict):
        alert["risk_pre_score"] = risk_pre_score

    return _build_result(norm_log, alert, index, start, engine_status, ti_result, corr)



def _build_result(norm_log, alert, index, start, status,
                  ti_result=None, corr=None) -> dict:
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


def run(input_file: str, output_file: str, limit=None, use_llm=True):
    print("=" * 65)
    print("  SOC ASSISTANT v4.4 — STRICT RULE-FIRST PIPELINE")
    print("  Rule ALERT → RULE_ALERT (LLM skipped)")
    print("  Rule CLEAN → RULE_CLEAN (LLM skipped)")
    print("  Rule None  → LLM decides → LLM_ONLY / CLEAN")
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
            print("      LLM chain ready ✓")
        else:
            print("      [WARN] LLM unavailable — Rule engine only (ALERT/CLEAN/NO_ENGINE)")

    print("\n[3/5] Initialising engines...")
    rag_engine  = get_rag_engine() if use_llm else None
    ti_engine   = get_ti_engine()
    soar_engine = get_soar_engine()
    print("      TI engine ✓  |  SOAR engine ✓")

    print(f"\n[4/5] Analysing {len(norm_logs)} logs...")
    mode_label = (
        "Rule(ALERT|CLEAN)=final | Rule(None)→LLM(full log)→LLM_ONLY|CLEAN"
        if chain else "Rule engine only (LLM unavailable)"
    )
    print(f"      Mode: {mode_label}")
    print(f"      {'─'*60}")

    results       = []
    engine_counts = {}
    start_total   = time.time()

    for i, norm_log in enumerate(norm_logs):
        tag       = norm_log.get("log_type", "?")
        corr_flag = "🔗" if norm_log.get("_correlation", {}).get("is_campaign") else "  "
        print(f"  [{i+1:>3}/{len(norm_logs)}] {tag:<8} {corr_flag}", end=" ", flush=True)

        result = process_log(norm_log, chain, i, rag_engine, ti_engine, soar_engine)
        results.append(result)

        eng = result.get("status", "")
        engine_counts[eng] = engine_counts.get(eng, 0) + 1

        sev      = result["alert"].get("severity", "")
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
        atype    = result["alert"].get("alert_type", "CLEAN")[:25]
        rps      = result["alert"].get("risk_pre_score", 0)
        print(f"{sev_icon} {atype:<25}  [rps={rps:>3}] [{eng}]")


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

    campaigns = {}
    for r in results:
        c = r.get("correlation", {})
        if c.get("is_campaign"):
            campaigns[c.get("source_ip", "unknown")] = c

    output = {
        "metadata": {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "input_file":    input_file,
            "version":       "4.4-strict-rule-first",
            "mode":          mode_label,
            "llm_available": chain is not None,
            "pipeline_flow": (
                "Rule ALERT→RULE_ALERT(final,LLM skipped) | "
                "Rule CLEAN→RULE_CLEAN(final,LLM skipped) | "
                "Rule None→LLM→LLM_ONLY/CLEAN"
            ),
            "engines": ["RULE", "LLM"],
            "logic": {
                "rule_alert":      "RULE_ALERT — alert directe, LLM ignoré",
                "rule_clean":      "RULE_CLEAN — clean confirmé, LLM ignoré",
                "no_rule_match":   "LLM analyse le log complet — LLM_ONLY ou CLEAN",
                "llm_unavailable": "RULE_ALERT/CLEAN si règle, NO_ENGINE sinon",
            },
        },
        "statistics": {
            "total_logs_analysed": len(results),
            "alert_summary": {
                "alerts_generated": len(alerts),
                "true_positives":   len(tps),
                "false_positives":  len(fps),
                "escalated":        len(escalated),
                "no_alert":         len(results) - len(alerts),
            },
            "engine_distribution":      engine_counts,
            "severity_distribution":    sev_dist,
            "attack_type_distribution": type_dist,
            "hallucination_stats":      halluc_summary,
            "campaign_count":           len(campaigns),
            "duration_sec":             round(time.time() - start_total, 2),
        },
        "campaigns": list(campaigns.values()),
        "results":   results,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n[5/5] Written: {output_file}")
    print(f"\n{'═'*65}")
    print(f"  Logs analysed     : {len(results)}")
    print(f"  Alerts            : {len(alerts)}")
    print(f"  True Positives    : {len(tps)}")
    print(f"  False Positives   : {len(fps)}")
    print(f"  Escalated L2      : {len(escalated)}")
    print(f"  Campaigns         : {len(campaigns)}")
    print(f"  Duration          : {round(time.time() - start_total, 2)}s")
    print(f"\n  Engine distribution:")
    for eng, cnt in sorted(engine_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(cnt, 30)
        print(f"    {eng:<30}  {bar} ({cnt})")
    print(f"{'═'*65}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOC Assistant v4.4 — Rule(ALERT|CLEAN)=final | Rule(None)=LLM"
    )
    parser.add_argument("--input",  default="data/logs.json",           help="Input raw logs JSON")
    parser.add_argument("--output", default="data/results_docker.json", help="Output results JSON")
    parser.add_argument("--limit",  type=int,                           help="Max logs to process")
    parser.add_argument("--no-llm", action="store_true",                help="Rule engine only (no LLM)")
    args = parser.parse_args()

    run(
        input_file=args.input,
        output_file=args.output,
        limit=args.limit,
        use_llm=not args.no_llm,
    )