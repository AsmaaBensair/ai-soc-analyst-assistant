"""
chain.py — LLM connectivity for SOC pipeline.

Responsibilities:
  - test_ollama_connection(): probe Ollama at runtime, return (bool, host_used)
  - build_llm()            : return a configured ChatOllama instance
  - build_chain()          : kept for legacy callers; returns (llm, prompt) pair
  - safe_parse_json()      : robustly parse LLM text → dict
  - analyze_log()          : thin wrapper kept for backward-compat (not used by main.py fast path)

FIX 1 — test_ollama_connection() now reads OLLAMA_HOST at call time (not module-load time),
         so Docker env-var injection works correctly.
FIX 2 — build_chain() now returns the ChatOllama instance directly so main.py's
         _call_llm_fast() can reuse it instead of creating a new instance per log.
FIX 3 — analyze_log() rewritten to use the llm instance directly; removed broken
         chain.steps[-1] / chain.last access that fails on modern LangChain.
FIX 4 — safe_parse_json() strips trailing ``` correctly (was missing the closing fence).
"""

import os
import json
import re
import requests

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import SystemMessage, HumanMessage

from prompts import SYSTEM_PROMPT


# ── Connection ────────────────────────────────────────────────────────────────

def _get_host() -> str:
    """Always read from env at call time so Docker injection works."""
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


def _get_model() -> str:
    return os.environ.get("OLLAMA_MODEL", "llama3")


def test_ollama_connection() -> bool:
    """
    Probe Ollama. Reads OLLAMA_HOST from environment at call time.
    Returns True if reachable, False otherwise.
    """
    host = _get_host()
    try:
        r = requests.get(f"{host}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        print(f"[OK] Ollama at {host} — models: {models}")
        return True
    except Exception as e:
        print(f"[WARN] Ollama unavailable at {host}: {e}")
        return False


# ── LLM factory ───────────────────────────────────────────────────────────────

def build_llm() -> ChatOllama:
    """
    Build and return a ChatOllama instance.
    Called once in run() / run_on_logs() and reused for all logs.
    Reads env vars at call time.
    """
    return ChatOllama(
        model=_get_model(),
        base_url=_get_host(),
        temperature=0,
        num_predict=300,
    )


def build_chain() -> ChatOllama:
    """
    Returns the ChatOllama instance (the 'chain' used throughout main.py).
    The legacy prompt | llm chain is no longer needed because main.py uses
    _call_llm_fast() with explicit SystemMessage/HumanMessage construction.
    Kept as build_chain() so existing call-sites in main.py need no change.
    """
    return build_llm()


# ── JSON parsing ──────────────────────────────────────────────────────────────

def safe_parse_json(response) -> dict:
    """
    Robustly parse an LLM response to a dict.
    Handles: AIMessage objects, markdown fences (```json ... ```), plain text.
    """
    try:
        text = response.content if hasattr(response, "content") else str(response)
        # Strip opening AND closing markdown fences
        text = re.sub(r"```(?:json)?", "", text).strip()
        text = text.rstrip("`").strip()
        return json.loads(text)
    except Exception:
        pass

    # Fallback: extract first {...} block
    try:
        match = re.search(r"\{.*\}", str(response), re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass

    return {
        "is_alert":   False,
        "error":      "Could not parse LLM JSON output",
        "raw_output": str(response)[:500],
    }


# ── Legacy wrapper ────────────────────────────────────────────────────────────

def analyze_log(log_str: str, chain: ChatOllama) -> dict:
    """
    Legacy entry point kept for backward compatibility.
    main.py fast path uses _call_llm_fast() directly and does NOT call this.

    FIX: previously tried chain.steps[-1] / chain.last which do not exist on
    ChatOllama or RunnableSequence in modern LangChain — replaced with direct
    llm.invoke() using the passed ChatOllama instance.
    """
    try:
        print("[DEBUG] Sending to LLM (analyze_log)…")
        messages = [
            SystemMessage(content=SYSTEM_PROMPT.replace("{{", "{").replace("}}", "}")),
            HumanMessage(content=f"Analyze this security log and return ONLY valid JSON:\n\n{log_str}"),
        ]
        result = chain.invoke(messages)
        print("[DEBUG] LLM replied")
        return safe_parse_json(result)
    except Exception as e:
        print(f"[DEBUG] LLM ERROR: {e}")
        return {"is_alert": False, "error": str(e)}