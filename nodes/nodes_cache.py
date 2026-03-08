"""Cache checking and saving nodes"""
from copy import deepcopy
from datetime import datetime, timezone
from soc_state import SOCState
from backends.cache_backend import cache_get, cache_set
from backends.rag_backend import vector_search, rag_list_parser


CACHE_ENGINE_VERSION = "rule_llmfirst_2026_03_08_v3_plaintext_fastallow"


def _build_single_output_snapshot(state: SOCState, item: dict, index: int) -> dict:
    """Build a single-request full output payload for caching."""
    result_json = state.get("result_json", {}) or {}
    result_rows = result_json.get("results", []) if isinstance(result_json, dict) else []

    result_row = {}
    if isinstance(result_rows, list) and index < len(result_rows) and isinstance(result_rows[index], dict):
        result_row = deepcopy(result_rows[index])

    return {
        "requests": [item.get("raw_request", "")],
        "items": [deepcopy(item)],
        "results": [],
        "result_json": {
            "results": [result_row] if result_row else [],
            "flow_version": result_json.get("flow_version", "capstone_http_analyzer.hybrid.v1") if isinstance(result_json, dict) else "capstone_http_analyzer.hybrid.v1",
            "generated_at": result_json.get("generated_at") if isinstance(result_json, dict) else None,
        },
    }


def cache_check_node(state: SOCState) -> dict:
    """
    Check if request results are already cached.
    If cached, populate cache_hit=True and copy cached analysis.
    If not cached, set cache_hit=False and continue to rule engine.
    RAG context is no longer handled here; it should be computed in a
    dedicated rag node earlier in the graph.
    """
    for item in state.get("items", []):
        raw_request = item["raw_request"]
        
        # Cache lookup only – rag_context is expected to exist already
        cached_data = cache_get(raw_request)
        
        if cached_data and cached_data.get("engine_version") == CACHE_ENGINE_VERSION:
            # Cache HIT - restore full snapshot if available, else fallback to summary fields.
            cached_full = cached_data.get("full_output")
            cached_items = cached_full.get("items", []) if isinstance(cached_full, dict) else []

            if isinstance(cached_items, list) and cached_items and isinstance(cached_items[0], dict):
                for key, value in cached_items[0].items():
                    item[key] = deepcopy(value)
            else:
                item["attack_type"] = cached_data.get("attack_type")
                item["rule_score"] = cached_data.get("rule_score")
                item["severity"] = cached_data.get("severity")
                item["fast_decision"] = cached_data.get("fast_decision")
                item["evidence"] = cached_data.get("evidence")
                item["attack_candidates"] = cached_data.get("attack_candidates")
                item["blocked"] = cached_data.get("blocked")
                item["final_msg"] = cached_data.get("final_msg")
                item["llm_output"] = cached_data.get("llm_output")

            item["cache_hit"] = True
            item["cached_result"] = cached_full if isinstance(cached_full, dict) else {}
        else:
            # Cache MISS - mark for analysis
            item["cache_hit"] = False
    
    return state


def cache_save_node(state: SOCState) -> dict:
    """
    Save analyzed results to cache for future requests.
    Only cache after full analysis (rule + LLM).
    """
    for index, item in enumerate(state.get("items", [])):
        raw_request = item["raw_request"]
        
        # Skip cache writes for items that were already loaded from cache.
        if item.get("cache_hit"):
            continue

        # Skip if analysis has not produced a final message yet.
        if not item.get("final_msg"):
            continue

        existing = cache_get(raw_request)
        if existing and existing.get("engine_version") == CACHE_ENGINE_VERSION:
            continue

        full_output = _build_single_output_snapshot(state, item, index)
        cache_data = {
            "raw_request": raw_request,
            "attack_type": item.get("attack_type"),
            "rule_score": item.get("rule_score"),
            "severity": item.get("severity"),
            "fast_decision": item.get("fast_decision"),
            "evidence": item.get("evidence"),
            "attack_candidates": item.get("attack_candidates"),
            "blocked": item.get("blocked"),
            "final_msg": item.get("final_msg"),
            "llm_output": item.get("llm_output"),
            "engine_version": CACHE_ENGINE_VERSION,
            "cache_written_at": datetime.now(timezone.utc).isoformat(),
            "full_output": full_output,
        }

        # Save to cache backend
        cache_set(raw_request, cache_data)
    
    return state
