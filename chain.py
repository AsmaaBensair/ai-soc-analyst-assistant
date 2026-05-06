"""
chain.py — LLM Chain Builder for SOC Assistant v3.0
"""

import os
import json
import re
import requests

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from prompts import SYSTEM_PROMPT

OLLAMA_HOST  = os.environ.get("OLLAMA_HOST",  "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")


def test_ollama_connection() -> bool:
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        print(f"[OK] Ollama at {OLLAMA_HOST} — models: {models}")
        return True
    except Exception as e:
        print(f"[WARN] Ollama unavailable: {e}")
        return False


def build_llm() -> ChatOllama:
    return ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_HOST,
        temperature=0,
        num_predict=1500,
    )


def build_chain():
    llm = build_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human",
         "Analyze the following security log and return ONLY a valid JSON object.\n\n"
         "{log_entry}"),
    ])
    return prompt | llm


def safe_parse_json(response) -> dict:
    try:
        text = response.content if hasattr(response, "content") else str(response)
        text = re.sub(r"```(?:json)?", "", text).strip()
        return json.loads(text)
    except Exception:
        pass
    try:
        match = re.search(r"\{.*\}", str(response), re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass
    return {
        "is_alert": False,
        "error": "Could not parse LLM JSON output",
        "raw_output": str(response)[:500],
    }


def analyze_log(log_str: str, chain) -> dict:
    try:
        result = chain.invoke({"log_entry": log_str})
        return safe_parse_json(result)
    except Exception as e:
        return {"is_alert": False, "error": str(e)}