
import re
import json
from typing import List, Dict, Optional
from collections import defaultdict

MALICIOUS_AGENTS = [
    "sqlmap", "masscan", "nmap", "nikto", "wpscan", "zgrab",
    "metasploit", "burpsuite", "burp suite", "acunetix", "nuclei",
    "dirbuster", "gobuster", "python-requests", "go-http-client",
    "zmap", "shodan", "nmap scripting engine", "curl/7",
]

ATTACK_PATTERNS = {
    "xss":     [r"<script", r"alert\s*\(", r"onerror\s*=", r"javascript:"],
    "sqli":    [r"union\s+select", r"or\s+1=1", r"sqlmap", r"sleep\s*\(",
                r"information_schema", r"drop\s+table"],
    "rce":     [r"(cmd|exec|system|execute)\s*=", r"\|\s*(id|whoami|cat)",
                r";\s*(ls|cat|wget|curl)", r"bash\s*-i", r"/dev/tcp/"],
    "lfi":     [r"\.\./", r"/etc/passwd", r"/etc/shadow", r"/var/log"],
    "scan":    [r"(sqlmap|nikto|nmap|masscan|wpscan|gobuster|nuclei|zgrab|burp)"],
    "upload":  [r"webshell", r"\.php\?cmd=", r"shell\.php"],
    "privesc": [r"sudo\s*:", r"USER=root", r"uid=0"],
}

INTERNAL_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)"
)


def is_internal_ip(ip: Optional[str]) -> bool:
    return bool(ip and INTERNAL_IP_RE.match(ip))


def detect_attack_patterns(text: Optional[str]) -> List[str]:
    if not text:
        return []
    found = []
    for k, patterns in ATTACK_PATTERNS.items():
        if any(re.search(p, text, re.IGNORECASE) for p in patterns):
            found.append(k)
    return found


def is_malicious_agent(agent: Optional[str]) -> bool:
    if not agent:
        return False
    a = agent.lower()
    return any(tool in a for tool in MALICIOUS_AGENTS)


def extract_ip(text: str) -> Optional[str]:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else None


def build_ecs(raw: dict) -> dict:
    log_type = raw.get("type", "unknown")
    ecs = {"event": {"dataset": log_type}}
    if log_type == "web":
        s = raw.get("status")
        ecs.update({
            "source": {"ip": raw.get("ip")},
            "http": {
                "request": {"method": raw.get("method")},
                "response": {"status_code": int(s) if s and str(s).isdigit() else None}
            },
            "url": {"path": raw.get("url")},
            "user_agent": {"original": raw.get("agent")}
        })
    elif log_type == "syslog":
        ecs.update({
            "host": {"hostname": raw.get("host")},
            "process": {"name": raw.get("process"), "pid": raw.get("pid")},
            "message": raw.get("message")
        })
    return ecs


def compute_fp_hint(raw: dict) -> dict:
    fp_score = 50
    tp, fp = [], []

    if raw.get("type") == "web":
        status = str(raw.get("status", ""))
        agent  = raw.get("agent", "")
        url    = raw.get("url", "")
        ip     = raw.get("ip", "")

        if status in ("301", "302", "404", "403", "401"):
            fp_score += 20
            fp.append(f"HTTP {status} response")
        if is_internal_ip(ip):
            fp_score += 30
            fp.append("Internal IP source")
        if is_malicious_agent(agent):
            fp_score -= 35
            tp.append("Malicious tool in User-Agent")
        hits = detect_attack_patterns(url)
        if hits:
            fp_score -= 25
            tp.append(f"Attack pattern in URL: {hits}")
        if status == "200" and (hits or is_malicious_agent(agent)):
            fp_score -= 20
            tp.append("HTTP 200 on attack request")

    elif raw.get("type") == "syslog":
        msg = raw.get("message", "").lower()
        if "failed password" in msg:
            fp_score -= 25
            tp.append("SSH brute force attempt")
        if "invalid user" in msg:
            fp_score -= 20
            tp.append("SSH user enumeration")
        if "accepted password" in msg:
            fp_score += 10
            fp.append("Successful login")
        if "sudo" in msg and "root" in msg:
            fp_score -= 15
            tp.append("Privilege escalation via sudo")

    fp_score = max(0, min(100, fp_score))
    return {
        "fp_score_hint": fp_score,
        "tp_signals": tp,
        "fp_signals": fp,
        "pre_assessment": (
            "LIKELY_TP" if fp_score <= 30 else
            "LIKELY_FP" if fp_score >= 70 else
            "UNCERTAIN"
        )
    }


def build_soc_enrichment(raw: dict, norm: dict) -> dict:
    fp_hint = norm.get("fp_hint", {})
    ip = norm.get("source_ip")
    score = fp_hint.get("fp_score_hint", 50)
    if score <= 20:
        risk_level = "CRITICAL"
    elif score <= 35:
        risk_level = "HIGH"
    elif score <= 55:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    return {
        "risk_level": risk_level,
        "attack_categories": norm.get("attack_hints", []),
        "is_external_threat": not is_internal_ip(ip) if ip else False,
        "needs_investigation": fp_hint.get("pre_assessment") != "LIKELY_FP",
        "enrichment_version": "3.0",
    }


def normalize_log(raw: dict) -> dict:
    log_type = raw.get("type", "unknown")
    normalized = {
        "raw_log": raw,
        "log_type": log_type,
        "timestamp": None,
        "source_ip": None,
        "target_host": raw.get("host"),
        "user": None,
        "process": raw.get("process"),
        "message": None,
        "status_code": None,
        "url": None,
        "user_agent": None,
        "is_internal": False,
        "attack_hints": [],
        "fp_hint": {},
        "ecs": build_ecs(raw),
        "soc_enrichment": {},
    }

    if log_type == "web":
        ip = raw.get("ip")
        url_hints = detect_attack_patterns(raw.get("url", ""))
        ua_hints  = detect_attack_patterns(raw.get("agent", ""))
        normalized.update({
            "timestamp":    raw.get("datetime"),
            "source_ip":    ip,
            "is_internal":  is_internal_ip(ip),
            "status_code":  raw.get("status"),
            "url":          raw.get("url"),
            "user_agent":   raw.get("agent"),
            "message":      f"{raw.get('method')} {raw.get('url')} [{raw.get('status')}]",
            "attack_hints": list(set(url_hints + ua_hints)),
        })

    elif log_type == "syslog":
        msg = raw.get("message", "")
        ip = extract_ip(msg)
        normalized.update({
            "timestamp":    f"{raw.get('month')} {raw.get('day')} {raw.get('time')}",
            "message":      msg,
            "source_ip":    ip,
            "is_internal":  is_internal_ip(ip),
            "attack_hints": detect_attack_patterns(msg),
        })

    else:
        raw_text = raw.get("raw", "")
        ip = extract_ip(raw_text)
        normalized.update({
            "message":      raw_text,
            "source_ip":    ip,
            "is_internal":  is_internal_ip(ip),
            "attack_hints": detect_attack_patterns(raw_text),
        })

    normalized["fp_hint"] = compute_fp_hint(raw)
    normalized["soc_enrichment"] = build_soc_enrichment(raw, normalized)
    return normalized



def correlate_logs(norm_logs: List[dict]) -> Dict[str, dict]:
    ip_groups: Dict[str, List[dict]] = defaultdict(list)
    for log in norm_logs:
        ip = log.get("source_ip")
        if ip:
            ip_groups[ip].append(log)

    correlations = {}
    for ip, logs in ip_groups.items():
        if len(logs) < 2:
            continue

        all_hints = []
        for log in logs:
            all_hints.extend(log.get("attack_hints", []))
        attack_types = list(set(all_hints))

        statuses = [str(l.get("status_code", "")) for l in logs]
        has_success = "200" in statuses
        failed_logins = sum(
            1 for l in logs
            if "failed password" in (l.get("message") or "").lower()
        )

        campaign_indicators = []
        if "scan" in attack_types and ("sqli" in attack_types or "lfi" in attack_types):
            campaign_indicators.append("RECON_THEN_EXPLOIT")
        if failed_logins >= 3:
            campaign_indicators.append("BRUTE_FORCE_CAMPAIGN")
        if "lfi" in attack_types and "rce" in attack_types:
            campaign_indicators.append("LFI_TO_RCE_CHAIN")
        if has_success and any(h in attack_types for h in ["sqli", "rce", "lfi", "xss", "upload"]):
            campaign_indicators.append("CONFIRMED_BREACH")
        if len(attack_types) >= 3:
            campaign_indicators.append("MULTI_VECTOR_ATTACK")

        risk_score = min(100, len(logs) * 4 + len(attack_types) * 12 + (25 if has_success else 0) + len(campaign_indicators) * 10)

        correlations[ip] = {
            "source_ip": ip,
            "log_count": len(logs),
            "attack_types": attack_types,
            "campaign_indicators": campaign_indicators,
            "has_successful_request": has_success,
            "failed_login_count": failed_logins,
            "correlation_risk_score": risk_score,
            "is_campaign": len(campaign_indicators) > 0,
            "correlation_summary": (
                f"IP {ip} triggered {len(logs)} events across {len(attack_types)} attack type(s). "
                + (f"Campaign: {', '.join(campaign_indicators)}." if campaign_indicators else "No campaign pattern detected.")
            )
        }
    return correlations


def format_log_for_llm(log: dict, index: int) -> str:
    hint = log.get("fp_hint", {})
    corr = log.get("_correlation", {})

    lines = [
        f"=== LOG #{index} ===",
        f"Type: {log['log_type']}",
        f"Source IP: {log['source_ip']}",
        f"URL: {log['url']}",
        f"Status: {log['status_code']}",
        f"User-Agent: {log.get('user_agent')}",
        f"Message: {log['message']}",
        f"Attack hints: {log['attack_hints']}",
        f"FP Score: {hint.get('fp_score_hint')} — Assessment: {hint.get('pre_assessment')}",
        f"TP Signals: {hint.get('tp_signals')}",
    ]
    if corr:
        lines.append(f"CORRELATION: {corr.get('correlation_summary', '')}")
        lines.append(f"CAMPAIGN: {corr.get('campaign_indicators', [])}")
        lines.append(f"CORR RISK: {corr.get('correlation_risk_score', 0)}/100")
    lines.append("====================")
    return "\n".join(lines)


def load_logs(filepath: str) -> List[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        raw_logs = json.load(f)
    norm_logs = [normalize_log(log) for log in raw_logs]
    correlations = correlate_logs(norm_logs)
    for log in norm_logs:
        ip = log.get("source_ip")
        if ip and ip in correlations:
            log["_correlation"] = correlations[ip]
    return norm_logs