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

    def fake_cache_get(raw_request: str):
        return in_memory_cache.get(raw_request)

    def fake_cache_set(raw_request: str, data: dict):
        in_memory_cache[raw_request] = data

    import nodes.nodes_cache as n_cache

    monkeypatch.setattr(n_cache, "cache_get", fake_cache_get)
    monkeypatch.setattr(n_cache, "cache_set", fake_cache_set)

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
        }
    )
    cache_save_node(first)

    second = _mk_state("2", request)
    result2 = cache_check_node(second)
    item = result2["items"][0]

    assert item["cache_hit"] is True
    assert item["attack_type"] == "SQL Injection"
    assert item["rule_score"] == 10
    assert item["fast_decision"] == "BLOCK"
