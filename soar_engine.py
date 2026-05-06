"""
soar_engine.py — SOAR Orchestration Engine (NEW v3)
SOC Assistant v3.0 — Enterprise Grade

Provides automated response playbooks triggered by alert types and severity.
No external connections — all actions are logged for human review.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict


# ─────────────────────────────────────────────
# PLAYBOOK DEFINITIONS
# ─────────────────────────────────────────────

PLAYBOOKS: Dict[str, dict] = {
    "Brute Force": {
        "name": "SSH Brute Force Response",
        "severity_threshold": "MEDIUM",
        "auto_actions": [
            "Block source IP at firewall (temporary 24h)",
            "Notify system administrator via email",
            "Add IP to threat watchlist",
            "Review SSH authentication logs for past 24h",
        ],
        "manual_actions": [
            "Verify if IP belongs to known partner — whitelist if needed",
            "Check if other accounts were targeted from same IP",
            "Consider implementing fail2ban or similar rate-limiting",
            "Review MFA enforcement policy for SSH access",
        ],
        "escalate_if": ["CONFIRMED_BREACH", "BRUTE_FORCE_CAMPAIGN"],
        "mitre_ref": "T1110 / TA0006",
    },
    "SQL Injection": {
        "name": "SQL Injection Response",
        "severity_threshold": "HIGH",
        "auto_actions": [
            "Block source IP at WAF immediately",
            "Capture full HTTP request for forensics",
            "Alert DBA team to review query logs",
            "Enable detailed SQL audit logging",
        ],
        "manual_actions": [
            "Review database for unauthorized data access or modification",
            "Check for data exfiltration in outbound traffic",
            "Validate all web application input validation rules",
            "Run application vulnerability scanner on affected endpoints",
        ],
        "escalate_if": ["CONFIRMED_BREACH", "MULTI_VECTOR_ATTACK"],
        "mitre_ref": "T1190 / TA0001",
    },
    "XSS": {
        "name": "Cross-Site Scripting Response",
        "severity_threshold": "HIGH",
        "auto_actions": [
            "Block source IP at WAF",
            "Log full request payload for analysis",
            "Alert web development team",
            "Check for session token theft in logs",
        ],
        "manual_actions": [
            "Identify all users who may have been affected",
            "Invalidate all active sessions as precaution",
            "Review Content-Security-Policy headers",
            "Patch vulnerable input fields with proper sanitization",
        ],
        "escalate_if": ["CONFIRMED_BREACH"],
        "mitre_ref": "T1190 / TA0001",
    },
    "Path Traversal": {
        "name": "Path Traversal / LFI Response",
        "severity_threshold": "HIGH",
        "auto_actions": [
            "Block source IP at WAF immediately",
            "Check accessed file paths in web server logs",
            "Alert security team with full request details",
            "Verify web application sandbox/chroot is active",
        ],
        "manual_actions": [
            "Identify if sensitive files were successfully read",
            "Review web server process permissions",
            "Implement stricter file access validation in code",
            "Check for follow-up exploitation attempts (RCE)",
        ],
        "escalate_if": ["CONFIRMED_BREACH", "LFI_TO_RCE_CHAIN"],
        "mitre_ref": "T1190 / TA0001",
    },
    "Command Injection": {
        "name": "RCE / Command Injection Response",
        "severity_threshold": "CRITICAL",
        "auto_actions": [
            "IMMEDIATE: Isolate affected host from network",
            "Block source IP at all perimeter controls",
            "Snapshot affected system for forensic analysis",
            "Alert SOC Level 2 and Incident Response team",
        ],
        "manual_actions": [
            "Full forensic analysis of affected host",
            "Check for persistence mechanisms (cron, systemd, etc.)",
            "Review all outbound connections from host",
            "Identify and patch vulnerable code path immediately",
        ],
        "escalate_if": ["CONFIRMED_BREACH", "LFI_TO_RCE_CHAIN", "MULTI_VECTOR_ATTACK"],
        "mitre_ref": "T1059 / TA0002",
    },
    "Malicious Scan": {
        "name": "Reconnaissance Scan Response",
        "severity_threshold": "MEDIUM",
        "auto_actions": [
            "Block source IP at firewall",
            "Log all requested endpoints for analysis",
            "Alert network security team",
            "Add IP to threat intelligence feed",
        ],
        "manual_actions": [
            "Review what information was exposed during scan",
            "Evaluate whether scan led to exploitation attempts",
            "Update IDS/IPS signatures for this scanner",
            "Check if scan originated from known threat actor",
        ],
        "escalate_if": ["RECON_THEN_EXPLOIT", "MULTI_VECTOR_ATTACK"],
        "mitre_ref": "T1046 / TA0007",
    },
    "Privilege Escalation": {
        "name": "Privilege Escalation Response",
        "severity_threshold": "HIGH",
        "auto_actions": [
            "Alert system administrator immediately",
            "Capture current process and user session details",
            "Review sudo/su logs for unauthorized use",
            "Lock suspicious user account pending investigation",
        ],
        "manual_actions": [
            "Review all commands executed with elevated privileges",
            "Check for unauthorized file modifications or new accounts",
            "Audit sudo configuration and privilege policies",
            "Determine how attacker gained initial access",
        ],
        "escalate_if": ["CONFIRMED_BREACH"],
        "mitre_ref": "T1548 / TA0004",
    },
    "Defense Evasion": {
        "name": "Defense Evasion / Log Tampering Response",
        "severity_threshold": "HIGH",
        "auto_actions": [
            "Preserve all available logs immediately (backup)",
            "Alert incident response team",
            "Check log integrity against known-good baseline",
            "Enable SIEM forwarding if not already active",
        ],
        "manual_actions": [
            "Identify what was deleted/modified and reconstruct timeline",
            "Review all user and system activity before deletion",
            "Check for additional persistence or lateral movement",
            "Forensically analyze the system for hidden malware",
        ],
        "escalate_if": ["CONFIRMED_BREACH"],
        "mitre_ref": "T1070 / TA0005",
    },
}

DEFAULT_PLAYBOOK = {
    "name": "Generic Security Incident Response",
    "auto_actions": [
        "Log and document the incident",
        "Notify on-call security analyst",
        "Collect relevant log evidence",
    ],
    "manual_actions": [
        "Assess scope and impact",
        "Determine remediation steps",
        "Update threat watchlist as needed",
    ],
    "escalate_if": [],
    "mitre_ref": "N/A",
}


# ─────────────────────────────────────────────
# SOAR ENGINE
# ─────────────────────────────────────────────

class SOAREngine:

    def get_playbook(self, alert_type: str) -> dict:
        return PLAYBOOKS.get(alert_type, DEFAULT_PLAYBOOK)

    def evaluate_auto_escalation(self, alert: dict, correlation: dict) -> dict:
        """Determine if alert should trigger automated escalation."""
        severity = alert.get("severity", "LOW")
        outcome  = alert.get("outcome", "unknown")
        is_tp    = alert.get("true_positive", False)
        alert_type = alert.get("alert_type", "")
        campaign_indicators = correlation.get("campaign_indicators", [])

        playbook = self.get_playbook(alert_type)
        escalate_triggers = playbook.get("escalate_if", [])

        reasons = []
        should_escalate = False

        if severity == "CRITICAL":
            should_escalate = True
            reasons.append("CRITICAL severity")

        if severity == "HIGH" and outcome == "success" and is_tp:
            should_escalate = True
            reasons.append("HIGH severity with successful outcome and confirmed TP")

        for indicator in campaign_indicators:
            if indicator in escalate_triggers:
                should_escalate = True
                reasons.append(f"Campaign indicator: {indicator}")

        if correlation.get("correlation_risk_score", 0) >= 80:
            should_escalate = True
            reasons.append(f"High correlation risk score: {correlation.get('correlation_risk_score')}")

        return {
            "auto_escalate": should_escalate,
            "escalation_reasons": reasons,
            "sla_response_minutes": 15 if should_escalate else 60,
        }

    def generate_soar_response(self, alert: dict, correlation: dict = None) -> dict:
        """Generate full SOAR response for an alert."""
        if correlation is None:
            correlation = {}

        alert_type = alert.get("alert_type", "Unknown")
        severity   = alert.get("severity", "LOW")
        playbook   = self.get_playbook(alert_type)
        escalation = self.evaluate_auto_escalation(alert, correlation)

        # Severity filter: only auto-act on threshold-meeting alerts
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        pb_threshold = playbook.get("severity_threshold", "HIGH")
        meets_threshold = severity_order.get(severity, 0) >= severity_order.get(pb_threshold, 3)

        return {
            "soar_version": "3.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "playbook_name": playbook["name"],
            "alert_type": alert_type,
            "severity": severity,
            "meets_playbook_threshold": meets_threshold,
            "auto_actions": playbook["auto_actions"] if meets_threshold else [],
            "manual_actions": playbook["manual_actions"],
            "auto_escalate": escalation["auto_escalate"],
            "escalation_reasons": escalation["escalation_reasons"],
            "sla_response_minutes": escalation["sla_response_minutes"],
            "mitre_ref": playbook.get("mitre_ref", "N/A"),
            "ticket": self._generate_ticket(alert, playbook, escalation),
        }

    def _generate_ticket(self, alert: dict, playbook: dict, escalation: dict) -> dict:
        """Generate a simulated ITSM/SOAR ticket."""
        severity = alert.get("severity", "LOW")
        prefix = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}.get(severity, "P4")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return {
            "ticket_id": f"{prefix}-SOC-{ts}",
            "priority": severity,
            "status": "OPEN",
            "assigned_to": "SOC Level 2" if escalation["auto_escalate"] else "SOC Level 1",
            "title": f"[{severity}] {alert.get('alert_type','Security Alert')} from {alert.get('source_ip','Unknown')}",
            "description": alert.get("summary", "Security alert detected by AI SOC pipeline"),
            "sla_deadline_minutes": escalation["sla_response_minutes"],
        }


_soar_instance = None

def get_soar_engine() -> SOAREngine:
    global _soar_instance
    if _soar_instance is None:
        _soar_instance = SOAREngine()
    return _soar_instance