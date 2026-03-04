"""Tests for the LLM batching feature."""
import sys
import time
from pathlib import Path

# ensure project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from graph_app import soc_app
import backends.llm_backend as lb
import nodes.nodes_rag as n_rag
import nodes.nodes_llm as n_llm


def test_bulk_invoked(monkeypatch):
    calls = {"single": 0, "bulk": 0}

    def fake_single(q, ctx):
        calls["single"] += 1
        return {"analysis": {"threat_score": 0, "attack_type": "Normal", "justification": "ok", "action": "ALLOW"}}

    def fake_bulk(qs, cs):
        calls["bulk"] += 1
        return [{"analysis": {"threat_score": 0, "attack_type": "Normal", "justification": "ok", "action": "ALLOW"}} for _ in qs]

    monkeypatch.setattr(lb, "llm_analyze", fake_single)
    monkeypatch.setattr(lb, "llm_bulk_analyze", fake_bulk)
    monkeypatch.setattr(n_llm, "llm_analyze", fake_single)
    monkeypatch.setattr(n_llm, "llm_bulk_analyze", fake_bulk)
    # stub out rag so tests don't hit Qdrant
    monkeypatch.setattr(n_rag, "vector_search", lambda q, k=3: [])
    # clear global cache dict to force misses
    import backends.cache_backend as cb
    cb._CACHE.clear()
    # ensure cache miss by patching node-level cache helpers
    import nodes.nodes_cache as n_cache
    monkeypatch.setattr(n_cache, "cache_get", lambda txt: None)
    monkeypatch.setattr(n_cache, "cache_set", lambda txt, val: None)

    payload = {"requests": ["q=" for _ in range(3)]}
    result = soc_app.invoke(payload)
    assert len(result["result_json"]["results"]) == 3
    assert calls["bulk"] == 1
    assert calls["single"] == 0


def test_bulk_fallback_to_single(monkeypatch):
    """If bulk helper raises, node should fallback to single-call mode."""
    def fake_bulk(qs, cs):
        raise RuntimeError("fail")

    single_calls = {"count": 0}

    def fake_single(q, ctx):
        single_calls["count"] += 1
        return {"analysis": {"threat_score": 0, "attack_type": "Normal", "justification": "ok", "action": "ALLOW"}}

    monkeypatch.setattr(lb, "llm_bulk_analyze", fake_bulk)
    monkeypatch.setattr(lb, "llm_analyze", fake_single)
    monkeypatch.setattr(n_llm, "llm_bulk_analyze", fake_bulk)
    monkeypatch.setattr(n_llm, "llm_analyze", fake_single)
    monkeypatch.setattr(n_rag, "vector_search", lambda q, k=3: [])
    # clear cache
    import backends.cache_backend as cb
    cb._CACHE.clear()
    import nodes.nodes_cache as n_cache
    monkeypatch.setattr(n_cache, "cache_get", lambda txt: None)
    monkeypatch.setattr(n_cache, "cache_set", lambda txt, val: None)

    payload = {"requests": ["q=" for _ in range(4)]}
    result = soc_app.invoke(payload)
    assert len(result["result_json"]["results"]) == 4
    assert single_calls["count"] == 4


def test_performance(monkeypatch):
    # simulate delay: bulk = .1s, single = .1s each
    def slow_single(q, ctx):
        time.sleep(0.1)
        return {"analysis": {"threat_score": 0, "attack_type": "Normal", "justification": "ok", "action": "ALLOW"}}
    def slow_bulk(qs, cs):
        time.sleep(0.1)
        return [{"analysis": {"threat_score": 0, "attack_type": "Normal", "justification": "ok", "action": "ALLOW"}} for _ in qs]
    monkeypatch.setattr(lb, "llm_analyze", slow_single)
    monkeypatch.setattr(lb, "llm_bulk_analyze", slow_bulk)
    monkeypatch.setattr(n_llm, "llm_analyze", slow_single)
    monkeypatch.setattr(n_llm, "llm_bulk_analyze", slow_bulk)
    monkeypatch.setattr(n_rag, "vector_search", lambda q, k=3: [])
    # clear global cache and patch node-level helpers
    import backends.cache_backend as cb
    cb._CACHE.clear()
    import nodes.nodes_cache as n_cache
    monkeypatch.setattr(n_cache, "cache_get", lambda txt: None)
    monkeypatch.setattr(n_cache, "cache_set", lambda txt, val: None)

    payload = {"requests": ["q=" for _ in range(5)]}
    t0 = time.time()
    soc_app.invoke(payload)
    t_bulk = time.time() - t0

    # force bulk failure to use single path
    monkeypatch.setattr(lb, "llm_bulk_analyze", lambda q,c: (_ for _ in ()).throw(Exception()))
    monkeypatch.setattr(n_llm, "llm_bulk_analyze", lambda q,c: (_ for _ in ()).throw(Exception()))
    t0 = time.time()
    soc_app.invoke(payload)
    t_single = time.time() - t0

    # bulk should not be slower than performing singles back-to-back
    assert t_bulk <= t_single + 0.01
