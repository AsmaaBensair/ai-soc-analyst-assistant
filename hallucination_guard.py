"""
hallucination_guard.py — Anti-hallucination validation for generated SOC alerts
SOC Assistant v3.0 — Enterprise Grade
"""

import json
import re
from typing import List, Optional


def extract_raw_values(log_entry: dict) -> set:
    values = set()
    def _walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)
        elif obj is not None:
            values.add(str(obj).lower().strip())
    _walk(log_entry)
    return values


def validate_alert(raw_log: dict, generated_alert: dict) -> dict:
    log_str = json.dumps(raw_log).lower()
    issues:   List[str] = []
    warnings: List[str] = []

    def _is_in_log(val: Optional[str]) -> bool:
        if not val:
            return True
        return str(val).lower().strip() in log_str

    src_ip = generated_alert.get("source_ip")
    if src_ip and not _is_in_log(src_ip):
        issues.append(f"[HALLUCINATION:IP] '{src_ip}' not found in raw log")

    user = generated_alert.get("user")
    if user:
        if user.lower() in ("n/a", "unknown", "administrator", "admin", "anonymous"):
            issues.append(f"[HALLUCINATION:USER] '{user}' is a placeholder not in raw log")
        elif not _is_in_log(user):
            issues.append(f"[HALLUCINATION:USER] '{user}' not found in raw log")

    host = generated_alert.get("target_host")
    if host and not _is_in_log(host):
        warnings.append(f"[WARN:HOST] '{host}' not confirmed in raw log")

    url = generated_alert.get("target_url")
    if url:
        decoded_url = re.sub(r"%[0-9a-fA-F]{2}", "", str(url)).lower().strip()
        if decoded_url and decoded_url not in log_str:
            path_part = decoded_url.split("?")[0]
            if path_part and path_part not in log_str:
                issues.append(f"[HALLUCINATION:URL] '{url}' not found in raw log")

    for ev in generated_alert.get("attack_evidence", []):
        if not ev or len(str(ev).strip()) < 5:
            continue
        words = [w for w in str(ev).split() if len(w) > 4]
        if words:
            matched = sum(1 for w in words[:6] if w.lower() in log_str)
            if matched == 0:
                issues.append(f"[HALLUCINATION:EVIDENCE] '{str(ev)[:80]}' has no match in raw log")

    is_tp = generated_alert.get("true_positive", False)
    is_fp = generated_alert.get("false_positive", False)
    if is_tp and is_fp:
        issues.append("[LOGIC_ERROR] true_positive and false_positive cannot both be True")

    severity  = generated_alert.get("severity", "")
    fp_score  = generated_alert.get("false_positive_score", 50)
    if severity == "CRITICAL" and isinstance(fp_score, (int, float)) and fp_score > 60:
        warnings.append(f"[WARN:SEVERITY] CRITICAL severity with high FP score ({fp_score}) — inconsistent")

    # v3: risk_score consistency check
    risk_score = generated_alert.get("risk_score", None)
    if risk_score is not None and not (0 <= risk_score <= 100):
        warnings.append(f"[WARN:RISK_SCORE] risk_score {risk_score} out of 0-100 range")

    hallucination_score = round(len(issues) / max(len(issues) + 5, 1), 2)

    generated_alert.update({
        "hallucination_detected":  len(issues) > 0,
        "hallucination_flags":     issues,
        "hallucination_warnings":  warnings,
        "hallucination_score":     hallucination_score,
    })
    return generated_alert


def validate_fp_classification(raw_log: dict, alert: dict) -> dict:
    flags: List[str] = []
    status  = str(raw_log.get("status", ""))
    url     = raw_log.get("url", "") or ""
    is_tp   = alert.get("true_positive", False)
    is_fp   = alert.get("false_positive", False)

    if status in ("403", "404", "401") and is_tp:
        flags.append(f"[FP_LOGIC] HTTP {status} request classified as TP — should be FP/uncertain")

    if status == "200" and any(p in url.lower() for p in ["/etc", "passwd", "shadow"]) and is_fp:
        flags.append("[FP_LOGIC] HTTP 200 on sensitive path classified as FP — should be TP")

    alert["fp_validation_flags"] = flags
    return alert


def summarize_hallucinations(results: list) -> dict:
    alert_results = [r for r in results if r.get("alert", {}).get("is_alert")]
    hallucinated  = [r for r in alert_results if r.get("alert", {}).get("hallucination_detected")]
    all_flags = []
    for r in results:
        all_flags.extend(r.get("alert", {}).get("hallucination_flags", []))
    return {
        "total_logs":          len(results),
        "total_alerts":        len(alert_results),
        "hallucinated_alerts": len(hallucinated),
        "hallucination_rate":  round(len(hallucinated) / max(len(alert_results), 1) * 100, 1),
        "total_flags":         len(all_flags),
        "flag_breakdown":      all_flags[:20],
    }