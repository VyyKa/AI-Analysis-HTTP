"""Regression tests for response_builder risk score aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from builders.response_builder import response_builder


def _base_item():
    return {
        "id": "item-1",
        "raw_request": "GET / HTTP/1.1",
        "attack_type": "Cross-Site Scripting",
        "rule_score": 0,
        "severity": "Info",
        "fast_decision": "BLOCK",
        "evidence": ["no_pattern_match"],
        "attack_candidates": [],
        "blocked": True,
        "cache_hit": False,
        "cached_result": {},
        "rag_context": "",
        "llm_output": {
            "analysis": {
                "threat_score": 8,
                "attack_type": "XSS",
                "justification": "encoded payload",
                "action": "BLOCK",
                "recommendation": "block",
            },
            "model": "llama-3.3-70b-versatile",
            "raw_text": "{}",
        },
        "final_msg": "[LLM] encoded payload (Score: 8, Action: BLOCK)",
        "hallucination_suspected": False,
    }


def test_risk_score_uses_llm_threat_when_rule_zero() -> None:
    state = {
        "requests": ["req"],
        "items": [_base_item()],
        "results": [],
        "result_json": {},
    }

    out = response_builder(state)
    first = out["result_json"]["results"][0]

    assert first["risk_score"] == 8
    assert first["severity"] == "High"


def test_risk_score_uses_max_of_rule_and_llm() -> None:
    item = _base_item()
    item["rule_score"] = 12
    item["severity"] = "Critical"

    state = {
        "requests": ["req"],
        "items": [item],
        "results": [],
        "result_json": {},
    }

    out = response_builder(state)
    first = out["result_json"]["results"][0]

    assert first["risk_score"] == 12
    assert first["severity"] == "Critical"
