"""
threat_intel.py — External Threat Intelligence Integration (NEW v3)
SOC Assistant v3.0 — Enterprise Grade

Provides IP reputation lookup via free/open TI feeds.
Falls back gracefully if offline.
"""

import re
import json
import hashlib
import time
import os
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─────────────────────────────────────────────
# EMBEDDED KNOWN-BAD IP / CIDR LIST
# (Tor exit nodes, common scanner ranges, etc.)
# ─────────────────────────────────────────────

KNOWN_MALICIOUS_IPS = {
    # Tor exit nodes (sample)
    "185.220.101.47", "185.220.100.240", "185.220.101.32",
    # Common scanner ranges observed in honeypots
    "45.33.32.156", "45.153.160.140", "91.92.249.13",
    "103.75.190.9", "5.188.86.172", "159.65.100.22",
    # Known attack infrastructure
    "77.88.21.33", "209.85.167.201", "37.9.13.199",
}

KNOWN_MALICIOUS_ASNS = {
    "AS14061",   # DigitalOcean (commonly abused)
    "AS16276",   # OVH (commonly abused)
    "AS24940",   # Hetzner (commonly abused)
}

# Simple /8 blocklist for known bad netblocks
BAD_PREFIXES = [
    "185.220.",  # Tor infrastructure
    "5.188.",    # Known bulletproof hosting
    "91.92.",    # Scanner ranges
    "103.75.",   # Asia-Pacific scanners
]

CACHE_FILE = "data/ti_cache.json"
CACHE_TTL_SECONDS = 3600  # 1 hour


class ThreatIntelEngine:
    def __init__(self):
        self._cache: dict = {}
        self._load_cache()

    def _load_cache(self):
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, "r") as f:
                    self._cache = json.load(f)
        except Exception:
            self._cache = {}

    def _save_cache(self):
        try:
            os.makedirs("data", exist_ok=True)
            with open(CACHE_FILE, "w") as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def _cache_get(self, ip: str) -> Optional[dict]:
        entry = self._cache.get(ip)
        if not entry:
            return None
        if time.time() - entry.get("cached_at", 0) > CACHE_TTL_SECONDS:
            return None
        return entry["data"]

    def _cache_set(self, ip: str, data: dict):
        self._cache[ip] = {
            "cached_at": time.time(),
            "data": data
        }
        self._save_cache()

    # ─────────────────────────────────────────
    # LOCAL REPUTATION CHECK (always available)
    # ─────────────────────────────────────────

    def local_reputation(self, ip: str) -> dict:
        """Check IP against embedded bad lists."""
        is_known_bad = ip in KNOWN_MALICIOUS_IPS
        in_bad_prefix = any(ip.startswith(pfx) for pfx in BAD_PREFIXES)

        tags = []
        if is_known_bad:
            tags.append("KNOWN_MALICIOUS")
        if in_bad_prefix:
            tags.append("SUSPICIOUS_NETBLOCK")
        # Check if Tor-like range
        if ip.startswith("185.220."):
            tags.append("TOR_EXIT_NODE")

        threat_score = 0
        if is_known_bad:
            threat_score += 80
        elif in_bad_prefix:
            threat_score += 50

        return {
            "source": "local_intel",
            "ip": ip,
            "is_known_malicious": is_known_bad,
            "tags": tags,
            "threat_score": min(100, threat_score),
            "reputation": "MALICIOUS" if threat_score >= 70 else
                          "SUSPICIOUS" if threat_score >= 40 else "CLEAN",
        }

    # ─────────────────────────────────────────
    # ABUSEIPDB (free API, optional)
    # ─────────────────────────────────────────

    def lookup_abuseipdb(self, ip: str, api_key: str) -> Optional[dict]:
        """Query AbuseIPDB for IP reputation. Requires free API key."""
        if not REQUESTS_AVAILABLE or not api_key:
            return None
        cached = self._cache_get(f"abuse_{ip}")
        if cached:
            return cached
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=5
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            result = {
                "source": "abuseipdb",
                "ip": ip,
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "reputation": "MALICIOUS" if data.get("abuseConfidenceScore", 0) >= 70 else
                              "SUSPICIOUS" if data.get("abuseConfidenceScore", 0) >= 25 else "CLEAN",
            }
            self._cache_set(f"abuse_{ip}", result)
            return result
        except Exception:
            return None

    # ─────────────────────────────────────────
    # MAIN ENRICH FUNCTION
    # ─────────────────────────────────────────

    def enrich_ip(self, ip: str) -> dict:
        """Full TI enrichment for an IP address."""
        if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return {"error": "Invalid IP", "ip": ip}

        local = self.local_reputation(ip)

        # Try AbuseIPDB if API key is set
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        remote = self.lookup_abuseipdb(ip, api_key) if api_key else None

        # Merge results
        combined_score = local["threat_score"]
        if remote:
            combined_score = max(combined_score, remote.get("abuse_confidence", 0))

        tags = local["tags"][:]
        if remote and remote.get("abuse_confidence", 0) >= 25:
            tags.append(f"ABUSEIPDB:{remote.get('abuse_confidence')}%")

        return {
            "ip": ip,
            "threat_score": combined_score,
            "reputation": "MALICIOUS" if combined_score >= 70 else
                          "SUSPICIOUS" if combined_score >= 30 else "CLEAN",
            "tags": tags,
            "local": local,
            "remote": remote,
            "enriched": True,
        }

    def enrich_batch(self, ips: list) -> dict:
        """Enrich multiple IPs at once."""
        return {ip: self.enrich_ip(ip) for ip in set(ips) if ip}


_ti_instance = None

def get_ti_engine() -> ThreatIntelEngine:
    global _ti_instance
    if _ti_instance is None:
        _ti_instance = ThreatIntelEngine()
    return _ti_instance