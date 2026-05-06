"""
evaluateur_complet.py — Alert Quality Evaluator v3.0
SOC Assistant v3.0 — Enterprise Grade
Scores on 12 dimensions including TI enrichment, SOAR, and correlation.
"""

import json
import argparse
from datetime import datetime

WEIGHTS = {
    "alert_generated":    2.0,
    "correct_alert_type": 2.0,
    "correct_severity":   1.5,
    "tp_fp_correct":      2.0,
    "fp_score_reasonable":1.0,
    "mitre_present":      0.5,
    "summary_grounded":   1.0,
    "no_hallucination":   1.5,
    "recommended_actions":0.5,
    "escalation_correct": 0.5,
    "risk_score_valid":   0.5,   # NEW v3
    "soar_present":       0.5,   # NEW v3
}
MAX_SCORE = sum(WEIGHTS.values())


class AlertEvaluateur:
    def __init__(self, results_file: str):
        self.results_file = results_file
        self.results:  list = []
        self.scores:   list = []
        self.metadata: dict = {}

    def load(self) -> bool:
        try:
            with open(self.results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.results  = data.get("results", [])
                self.metadata = data.get("metadata", {})
            else:
                self.results = data
            print(f"  Loaded {len(self.results)} results from {self.results_file}")
            return True
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def score_result(self, result: dict) -> dict:
        alert   = result.get("alert", {})
        raw_log = result.get("raw_log", {})
        raw_str = json.dumps(raw_log).lower()
        corr    = result.get("correlation", {})

        bd = {}
        total = 0.0

        is_alert = alert.get("is_alert", False)
        evidence = alert.get("attack_evidence", [])

        # 1. Alert Generated
        if is_alert and evidence:
            pts, reason = WEIGHTS["alert_generated"], "Alert with supporting evidence"
        elif is_alert:
            pts, reason = WEIGHTS["alert_generated"] * 0.5, "Alert without evidence"
        else:
            pts, reason = WEIGHTS["alert_generated"] * 0.7, "No alert (may be correct)"
        bd["alert_generated"] = {"score": round(pts,2), "max": WEIGHTS["alert_generated"], "reason": reason}
        total += pts

        # 2. Attack Type
        atype = alert.get("alert_type", "")
        known = ["Brute Force","XSS","SQL Injection","Path Traversal","Command Injection",
                 "Privilege Escalation","Defense Evasion","Malicious Scan","User Enumeration",
                 "Webshell"]
        if atype in known:
            pts, reason = WEIGHTS["correct_alert_type"], f"Known type: {atype}"
        elif atype and atype not in ("","False Positive","Suspicious"):
            pts, reason = WEIGHTS["correct_alert_type"] * 0.7, f"Unlisted type: {atype}"
        elif not is_alert:
            pts, reason = WEIGHTS["correct_alert_type"], "Correctly no alert"
        else:
            pts, reason = WEIGHTS["correct_alert_type"] * 0.2, "Vague/missing type"
        bd["correct_alert_type"] = {"score": round(pts,2), "max": WEIGHTS["correct_alert_type"], "reason": reason}
        total += pts

        # 3. Severity
        severity = alert.get("severity", "")
        fp_score = alert.get("false_positive_score", 50)
        outcome  = alert.get("outcome", "")
        if not severity:
            pts, reason = 0, "No severity"
        elif severity == "CRITICAL" and outcome == "success" and fp_score < 30:
            pts, reason = WEIGHTS["correct_severity"], "CRITICAL+success+low FP: calibrated"
        elif severity == "LOW" and fp_score > 65:
            pts, reason = WEIGHTS["correct_severity"], "LOW + high FP: correct"
        elif severity in ("HIGH","MEDIUM") and 20 <= fp_score <= 65:
            pts, reason = WEIGHTS["correct_severity"], f"{severity} FP={fp_score}: reasonable"
        elif severity == "CRITICAL" and fp_score > 55:
            pts, reason = WEIGHTS["correct_severity"] * 0.3, f"CRITICAL but FP={fp_score}: inconsistent"
        else:
            pts, reason = WEIGHTS["correct_severity"] * 0.6, f"Severity {severity}: uncertain"
        bd["correct_severity"] = {"score": round(pts,2), "max": WEIGHTS["correct_severity"], "reason": reason}
        total += pts

        # 4. TP/FP
        is_tp = alert.get("true_positive", False)
        is_fp = alert.get("false_positive", False)
        if is_tp and is_fp:
            pts, reason = 0, "ERROR: both TP and FP True"
        elif is_tp and fp_score <= 40:
            pts, reason = WEIGHTS["tp_fp_correct"], "TP=True, low FP score: consistent"
        elif is_fp and fp_score >= 60:
            pts, reason = WEIGHTS["tp_fp_correct"], "FP=True, high FP score: consistent"
        elif not is_tp and not is_fp:
            pts, reason = WEIGHTS["tp_fp_correct"] * 0.5, "Neither TP nor FP: ambiguous"
        else:
            pts, reason = WEIGHTS["tp_fp_correct"] * 0.3, f"TP/FP inconsistent with FP={fp_score}"
        bd["tp_fp_correct"] = {"score": round(pts,2), "max": WEIGHTS["tp_fp_correct"], "reason": reason}
        total += pts

        # 5. FP Score Range
        if isinstance(fp_score, (int, float)) and 0 <= fp_score <= 100:
            pts, reason = WEIGHTS["fp_score_reasonable"], f"FP={fp_score} valid"
        else:
            pts, reason = 0, f"FP score {fp_score} invalid"
        bd["fp_score_reasonable"] = {"score": round(pts,2), "max": WEIGHTS["fp_score_reasonable"], "reason": reason}
        total += pts

        # 6. MITRE
        has_mitre = (alert.get("mitre_tactic") not in (None,"null","") and
                     alert.get("mitre_technique_id") not in (None,"null",""))
        if has_mitre and is_alert:
            pts, reason = WEIGHTS["mitre_present"], f"{alert.get('mitre_tactic')} / {alert.get('mitre_technique_id')}"
        elif not is_alert:
            pts, reason = WEIGHTS["mitre_present"], "No MITRE for non-alert"
        else:
            pts, reason = 0, "Missing MITRE"
        bd["mitre_present"] = {"score": round(pts,2), "max": WEIGHTS["mitre_present"], "reason": reason}
        total += pts

        # 7. Summary Grounded
        verified = sum(1 for f in ("source_ip","target_host","user","target_url")
                       if alert.get(f) and str(alert.get(f)).lower() in raw_str)
        if verified >= 2:
            pts, reason = WEIGHTS["summary_grounded"], f"{verified} values verified in log"
        elif verified == 1:
            pts, reason = WEIGHTS["summary_grounded"] * 0.6, "1 value verified"
        elif not alert.get("summary"):
            pts, reason = 0, "No summary"
        else:
            pts, reason = WEIGHTS["summary_grounded"] * 0.3, "Summary unverified"
        bd["summary_grounded"] = {"score": round(pts,2), "max": WEIGHTS["summary_grounded"], "reason": reason}
        total += pts

        # 8. No Hallucination
        halluc  = alert.get("hallucination_detected", False)
        h_flags = alert.get("hallucination_flags", [])
        if not halluc:
            pts, reason = WEIGHTS["no_hallucination"], "No hallucinations"
        elif len(h_flags) == 1:
            pts, reason = WEIGHTS["no_hallucination"] * 0.5, f"Minor: {h_flags[0]}"
        else:
            pts, reason = 0, f"{len(h_flags)} hallucination flags"
        bd["no_hallucination"] = {"score": round(pts,2), "max": WEIGHTS["no_hallucination"], "reason": reason}
        total += pts

        # 9. Recommended Actions
        actions = alert.get("recommended_actions", [])
        if len(actions) >= 3:
            pts, reason = WEIGHTS["recommended_actions"], f"{len(actions)} actions"
        elif actions:
            pts, reason = WEIGHTS["recommended_actions"] * 0.6, f"{len(actions)} action(s)"
        else:
            pts, reason = 0, "No actions"
        bd["recommended_actions"] = {"score": round(pts,2), "max": WEIGHTS["recommended_actions"], "reason": reason}
        total += pts

        # 10. Escalation
        escalate   = alert.get("escalate_to_soc_level2")
        esc_reason = alert.get("escalation_reason", "")
        if escalate is not None and esc_reason:
            if severity in ("CRITICAL","HIGH") and is_tp and escalate:
                pts, reason = WEIGHTS["escalation_correct"], "Correctly escalated"
            elif severity in ("LOW","MEDIUM") and is_fp and not escalate:
                pts, reason = WEIGHTS["escalation_correct"], "Correctly not escalated"
            else:
                pts, reason = WEIGHTS["escalation_correct"] * 0.7, "Escalation present and justified"
        else:
            pts, reason = 0, "No escalation decision"
        bd["escalation_correct"] = {"score": round(pts,2), "max": WEIGHTS["escalation_correct"], "reason": reason}
        total += pts

        # 11. Risk Score Valid (NEW v3)
        risk_score = alert.get("risk_score")
        if risk_score is not None and isinstance(risk_score, (int, float)) and 0 <= risk_score <= 100:
            pts, reason = WEIGHTS["risk_score_valid"], f"Risk score {risk_score} valid"
        else:
            pts, reason = 0, "Missing or invalid risk score"
        bd["risk_score_valid"] = {"score": round(pts,2), "max": WEIGHTS["risk_score_valid"], "reason": reason}
        total += pts

        # 12. SOAR Present (NEW v3)
        soar = alert.get("soar_response", {})
        if soar and soar.get("playbook_name"):
            pts, reason = WEIGHTS["soar_present"], f"SOAR: {soar.get('playbook_name')}"
        elif not is_alert:
            pts, reason = WEIGHTS["soar_present"], "No SOAR for non-alert"
        else:
            pts, reason = 0, "No SOAR response"
        bd["soar_present"] = {"score": round(pts,2), "max": WEIGHTS["soar_present"], "reason": reason}
        total += pts

        score_10 = round((total / MAX_SCORE) * 10, 2)

        return {
            "log_index":     result.get("log_index"),
            "result_id":     result.get("result_id"),
            "log_type":      result.get("log_type"),
            "source_ip":     result.get("source_ip"),
            "status":        result.get("status"),
            "is_alert":      is_alert,
            "alert_type":    atype,
            "severity":      severity,
            "true_positive": is_tp,
            "false_positive":is_fp,
            "fp_score":      fp_score,
            "risk_score":    alert.get("risk_score"),
            "is_campaign":   corr.get("is_campaign", False),
            "score_raw":     round(total, 2),
            "score_max":     round(MAX_SCORE, 2),
            "score_10":      score_10,
            "breakdown":     bd,
        }

    def evaluate(self):
        print(f"\n{'─'*60}\n  Evaluating alert quality...\n{'─'*60}")
        for result in self.results:
            self.scores.append(self.score_result(result))

    def print_report(self):
        if not self.scores:
            print("No scores computed.")
            return

        alert_scores = [s for s in self.scores if s["is_alert"]]
        tps = [s for s in self.scores if s["true_positive"]]
        fps = [s for s in self.scores if s["false_positive"]]
        avg = round(sum(s["score_10"] for s in self.scores) / max(len(self.scores), 1), 2)
        avg_alerts = round(sum(s["score_10"] for s in alert_scores) / max(len(alert_scores), 1), 2)

        grade = ("EXCELLENT 🏆" if avg >= 8.5 else
                 "GOOD ✅"      if avg >= 7.0 else
                 "AVERAGE ⚠"   if avg >= 5.5 else "POOR ❌")

        print(f"\n{'═'*60}")
        print("  ALERT QUALITY EVALUATION REPORT v3.0")
        print(f"{'═'*60}")
        print(f"  File   : {self.results_file}")
        print(f"  Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*60}")
        print(f"  Total results   : {len(self.scores)}")
        print(f"  Alerts          : {len(alert_scores)}")
        print(f"  True Positives  : {len(tps)}")
        print(f"  False Positives : {len(fps)}")
        print(f"  Overall score   : {avg}/10  ({grade})")
        print(f"  Alert score     : {avg_alerts}/10")

        print(f"\n  Severity Distribution:")
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            cnt = sum(1 for s in alert_scores if s["severity"] == sev)
            bar = "█" * cnt
            print(f"    {sev:<10}: {bar} ({cnt})")

        print(f"\n  Top Attack Types:")
        tc: dict = {}
        for s in alert_scores:
            t = s.get("alert_type","Unknown")
            tc[t] = tc.get(t,0) + 1
        for t, c in sorted(tc.items(), key=lambda x: -x[1])[:10]:
            print(f"    {t:<35}: {c}")

        if alert_scores:
            worst = sorted(alert_scores, key=lambda s: s["score_10"])[:3]
            print(f"\n  Lowest Scoring Alerts:")
            for w in worst:
                print(f"    [{w['score_10']}/10] Log#{w['log_index']} {w['alert_type']} — {w['source_ip']}")
                for cat, d in w["breakdown"].items():
                    if d["score"] < d["max"]:
                        print(f"      ↳ {cat}: {d['reason']}")
        print(f"\n{'═'*60}")

    def save_report(self, output_file: str):
        report = {
            "metadata": {
                "evaluated_at":   datetime.now().isoformat(),
                "source_file":    self.results_file,
                "version":        "3.0",
                "total_results":  len(self.scores),
                "scoring_weights":WEIGHTS,
                "max_score":      MAX_SCORE,
            },
            "summary": {
                "alerts_generated": sum(1 for s in self.scores if s["is_alert"]),
                "true_positives":   sum(1 for s in self.scores if s["true_positive"]),
                "false_positives":  sum(1 for s in self.scores if s["false_positive"]),
                "avg_quality_score":round(sum(s["score_10"] for s in self.scores)/max(len(self.scores),1), 2),
                "avg_risk_score":   round(sum((s.get("risk_score") or 0) for s in self.scores)/max(len(self.scores),1), 1),
            },
            "scored_results": self.scores,
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  Report saved: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alert Quality Evaluator v3.0")
    parser.add_argument("--input",  required=True)
    parser.add_argument("--output", default="data/evaluation_report.json")
    args = parser.parse_args()

    print("=" * 60)
    print("  Alert Quality Evaluator v3.0")
    print("=" * 60)

    ev = AlertEvaluateur(args.input)
    if ev.load():
        ev.evaluate()
        ev.print_report()
        ev.save_report(args.output)
