"""Verify graph routing puts RAG only on slow path and not on fast/cache-hit path."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from graph_app import soc_app
import nodes.nodes_rag as n_rag
import nodes.nodes_llm as n_llm
import nodes.nodes_cache as n_cache
import backends.cache_backend as cb


def run_state(request_text):
    # execute graph via invoke()
    return soc_app.invoke({"requests": [request_text]})


def test_slow_path_includes_rag(monkeypatch):
    cb._CACHE.clear()
    monkeypatch.setattr(n_cache, "cache_get", lambda txt: None)
    monkeypatch.setattr(n_cache, "cache_set", lambda txt, val: None)
    monkeypatch.setattr(n_rag, "vector_search", lambda q, k=3: [{"raw_request": "ctx", "label": "normal", "attack_type": "context"}])
    monkeypatch.setattr(n_llm, "llm_analyze", lambda q, c: {"analysis": {"threat_score": 1, "attack_type": "Benign", "justification": "ok", "action": "ALLOW"}, "model": "mock"})
    monkeypatch.setattr(n_llm, "llm_bulk_analyze", lambda qs, cs: [{"analysis": {"threat_score": 1, "attack_type": "Benign", "justification": "ok", "action": "ALLOW"}, "model": "mock"} for _ in qs])

    # choose a request that routes to slow path in rule engine
    result = run_state("q=")
    item = result["items"][0]
    output = result["result_json"]["results"][0]
    assert output.get("source") == "llm_explainer"
    assert "rag_context" in item, "RAG context should be added on slow path"
    assert item.get("rag_context") != "", "Slow path should provide rag context"


def test_fast_path_no_rag(monkeypatch):
    cb._CACHE.clear()
    monkeypatch.setattr(n_cache, "cache_get", lambda txt: None)
    monkeypatch.setattr(n_cache, "cache_set", lambda txt, val: None)
    # a clearly malicious request that triggers fast block
    result = run_state("SELECT * FROM users WHERE id=1' UNION SELECT *")
    item = result["items"][0]
    output = result["result_json"]["results"][0]
    assert item.get("fast_decision") == "BLOCK"
    assert output.get("source") == "rule_engine"
    # rag_context may be absent or empty
    assert item.get("rag_context", "") == "", "Fast path should skip RAG"


if __name__ == "__main__":
    print("Running flow tests for RAG placement")
    test_slow_path_includes_rag()
    print("Slow path test passed")
    test_fast_path_no_rag()
    print("Fast path test passed")
