import hashlib
import re
from typing import Optional

try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    print("[WARN] chromadb not installed → keyword fallback mode")

MITRE_KNOWLEDGE = [
    {"id": "T1110", "technique": "Brute Force", "tactic": "Credential Access",
     "tags": ["failed password", "invalid user", "ssh", "brute force"]},
    {"id": "T1190", "technique": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "tags": ["union select", "script", "passwd", "../", "sql injection", "xss", "lfi"]},
    {"id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution",
     "tags": ["cmd=", "exec=", "system", "bash", "rce", "whoami", "id"]},
    {"id": "T1046", "technique": "Network Service Discovery", "tactic": "Discovery",
     "tags": ["nmap", "masscan", "sqlmap", "nikto", "scan", "wpscan", "nuclei"]},
    {"id": "T1548", "technique": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
     "tags": ["sudo", "root", "uid=0", "privilege", "escalation"]},
    {"id": "T1070", "technique": "Indicator Removal", "tactic": "Defense Evasion",
     "tags": ["delete", "rm -rf", "log", "find", "evasion"]},
    {"id": "T1505.003", "technique": "Server Software Component: Web Shell", "tactic": "Persistence",
     "tags": ["webshell", "shell.php", "cmd=", "upload"]},
]


class SOCRagEngine:
    def __init__(self, persist_dir="./rag_db"):
        self.available = CHROMA_AVAILABLE
        self.persist_dir = persist_dir

        if self.available:
            try:
                self.client = chromadb.PersistentClient(path=persist_dir)
                ef = embedding_functions.DefaultEmbeddingFunction()
                self.mitre = self.client.get_or_create_collection("mitre", embedding_function=ef)
                self.alerts = self.client.get_or_create_collection("alerts", embedding_function=ef)
                self._seed()
            except Exception as e:
                print(f"[WARN] ChromaDB init failed: {e} → fallback mode")
                self.available = False

    def _seed(self):
        if self.mitre.count() == 0:
            docs, ids = [], []
            for m in MITRE_KNOWLEDGE:
                docs.append(f"{m['technique']} {m['tactic']} {' '.join(m['tags'])}")
                ids.append(m["id"])
            self.mitre.add(documents=docs, ids=ids)

    def retrieve(self, log_text: str) -> str:
        if not self.available:
            return self._keyword_fallback(log_text)
        try:
            query = self._clean_query(log_text)
            res = self.mitre.query(query_texts=[query], n_results=2)
            context = ["=== RAG MITRE CONTEXT ==="]
            for doc in res["documents"][0]:
                context.append(f"- {doc}")
            context.append("=== END RAG ===\n")
            return "\n".join(context)
        except Exception:
            return self._keyword_fallback(log_text)

    def _clean_query(self, log_text: str) -> str:
        patterns = re.findall(
            r"(failed password|union select|/etc/passwd|cmd=|sqlmap|webshell|sudo.*root|masscan|nikto|nuclei)",
            log_text.lower()
        )
        return " ".join(patterns) if patterns else log_text[:200]

    def _keyword_fallback(self, log_text: str) -> str:
        ll = log_text.lower()
        hits = []
        for m in MITRE_KNOWLEDGE:
            if any(tag in ll for tag in m["tags"]):
                hits.append(f"{m['technique']} ({m['id']}) — {m['tactic']}")
        if not hits:
            return ""
        return "RAG: " + " | ".join(hits) + "\n"

    def add_alert(self, log_text: str, alert: dict):
        if not self.available:
            return
        try:
            if self.alerts.count() > 10000:
                return
            uid = hashlib.md5(log_text.encode()).hexdigest()
            self.alerts.upsert(documents=[log_text[:300]], ids=[uid])
        except Exception:
            pass


_instance: Optional[SOCRagEngine] = None

def get_rag_engine() -> SOCRagEngine:
    global _instance
    if _instance is None:
        _instance = SOCRagEngine()
    return _instance