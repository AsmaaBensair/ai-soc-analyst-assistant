
import json
import os
from datetime import datetime, timezone
from typing import List, Dict

FEEDBACK_FILE = "data/analyst_feedback.json"


class FeedbackLoop:
    def __init__(self):
        self.feedback: List[dict] = []
        self.adjustments: Dict[str, float] = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(FEEDBACK_FILE):
                with open(FEEDBACK_FILE, "r") as f:
                    data = json.load(f)
                    self.feedback = data.get("feedback", [])
                    self.adjustments = data.get("adjustments", {})
        except Exception:
            pass

    def _save(self):
        os.makedirs("data", exist_ok=True)
        with open(FEEDBACK_FILE, "w") as f:
            json.dump({
                "feedback": self.feedback[-500:],  # keep last 500
                "adjustments": self.adjustments,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }, f, indent=2)

    def record_feedback(self, result_id: str, alert_type: str,
                        analyst_verdict: str, analyst_note: str = "") -> dict:
        """
        Record analyst feedback on an alert.
        analyst_verdict: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'UNCERTAIN'
        """
        entry = {
            "result_id": result_id,
            "alert_type": alert_type,
            "analyst_verdict": analyst_verdict,
            "analyst_note": analyst_note,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self.feedback.append(entry)

        # Update FP-score calibration
        key = alert_type
        current = self.adjustments.get(key, 0.0)
        if analyst_verdict == "FALSE_POSITIVE":
            self.adjustments[key] = round(current + 2.0, 1)  # bias toward FP
        elif analyst_verdict == "TRUE_POSITIVE":
            self.adjustments[key] = round(current - 2.0, 1)  # bias toward TP

        self._save()
        return entry

    def get_adjustment(self, alert_type: str) -> float:
        """Return FP score calibration adjustment for an alert type."""
        return self.adjustments.get(alert_type, 0.0)

    def get_stats(self) -> dict:
        total = len(self.feedback)
        tps = sum(1 for f in self.feedback if f["analyst_verdict"] == "TRUE_POSITIVE")
        fps = sum(1 for f in self.feedback if f["analyst_verdict"] == "FALSE_POSITIVE")
        return {
            "total_feedback": total,
            "analyst_tps": tps,
            "analyst_fps": fps,
            "analyst_uncertain": total - tps - fps,
            "calibration_adjustments": self.adjustments,
        }

    def get_all_feedback(self) -> List[dict]:
        return self.feedback


_feedback_instance = None

def get_feedback_loop() -> FeedbackLoop:
    global _feedback_instance
    if _feedback_instance is None:
        _feedback_instance = FeedbackLoop()
    return _feedback_instance