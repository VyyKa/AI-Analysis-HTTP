"""Test cache checking directly without full graph import"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from nodes.nodes_cache import cache_check_node, cache_save_node

def _mk_state(item_id: str, request: str) -> dict:
    return {
        "items": [
            {
                "id": item_id,
                "raw_request": request,
                "cache_hit": False,
                "attack_type": "",
                "rule_score": 0,
                "severity": "",
                "fast_decision": "",
                "evidence": [],
                "attack_candidates": [],
                "blocked": False,
            }
        ]
    }


def test_cache_check_and_save_roundtrip(monkeypatch):
    request = "/api/users?id=1 OR 1=1"
    in_memory_cache = {}
    captured_logs = []

    def fake_cache_get(raw_request: str):
        return in_memory_cache.get(raw_request)

    def fake_cache_set(raw_request: str, data: dict):
        in_memory_cache[raw_request] = data

    def fake_append_analysis_log(cache_key: str, log_data: dict):
        captured_logs.append((cache_key, log_data))

    import nodes.nodes_cache as n_cache

    monkeypatch.setattr(n_cache, "cache_get", fake_cache_get)
    monkeypatch.setattr(n_cache, "cache_set", fake_cache_set)
    monkeypatch.setattr(n_cache, "append_analysis_log", fake_append_analysis_log)

    first = _mk_state("1", request)
    result1 = cache_check_node(first)
    assert result1["items"][0]["cache_hit"] is False

    first["items"][0].update(
        {
            "attack_type": "SQL Injection",
            "rule_score": 10,
            "severity": "High",
            "fast_decision": "BLOCK",
            "evidence": ["SQL Injection"],
            "blocked": True,
            "final_msg": "[BLOCKED] SQL Injection | Score=10 | Severity=High",
        }
    )
    cache_save_node(first)

    saved_entry = in_memory_cache[request]
    assert "full_output" not in saved_entry
    assert "raw_request" not in saved_entry
    assert saved_entry["request_checksum"] == n_cache._make_key(request)
    assert captured_logs and captured_logs[0][0] == saved_entry["request_checksum"]

    second = _mk_state("2", request)
    result2 = cache_check_node(second)
    item = result2["items"][0]

    assert item["cache_hit"] is True
    assert item["attack_type"] == "SQL Injection"
    assert item["rule_score"] == 10
    assert item["fast_decision"] == "BLOCK"
