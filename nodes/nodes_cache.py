"""Cache checking and saving nodes"""
from copy import deepcopy
from datetime import datetime, timezone

from soc_state import SOCState
from backends.analysis_log_backend import append_analysis_log
from backends.cache_backend import _make_key, cache_get, cache_set


CACHE_ENGINE_VERSION = "rule_llmfirst_2026_03_08_v6_checksum_only"


def _build_cached_llm_output(item: dict) -> dict:
    """Persist only LLM fields needed for fast cache-hit replay."""
    llm_output = item.get("llm_output")
    if not isinstance(llm_output, dict):
        return {}

    analysis = llm_output.get("analysis")
    analysis_dict = analysis if isinstance(analysis, dict) else {}

    return {
        "model": llm_output.get("model"),
        "confidence": llm_output.get("confidence"),
        "analysis": {
            "threat_score": analysis_dict.get("threat_score", 0),
            "action": analysis_dict.get("action"),
            "verdict": analysis_dict.get("verdict"),
        },
    }


def _build_analysis_log(state: SOCState, item: dict, index: int, cache_key: str) -> dict:
    """Build rich analysis payload for append-only JSONL logs."""
    result_json = state.get("result_json", {}) or {}
    result_rows = result_json.get("results", []) if isinstance(result_json, dict) else []

    result_row = {}
    if isinstance(result_rows, list) and index < len(result_rows) and isinstance(result_rows[index], dict):
        result_row = deepcopy(result_rows[index])

    return {
        "cache_key": cache_key,
        "raw_request": item.get("raw_request", ""),
        "engine_version": CACHE_ENGINE_VERSION,
        "item": deepcopy(item),
        "result_json": {
            "result": result_row,
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
            # Cache HIT - replay the minimal cached verdict/state.
            item["attack_type"] = cached_data.get("attack_type", item.get("attack_type", "Unknown"))
            item["rule_score"] = cached_data.get("rule_score", item.get("rule_score", 0))
            item["severity"] = cached_data.get("severity", item.get("severity", "Info"))
            item["fast_decision"] = cached_data.get("fast_decision", item.get("fast_decision", "REVIEW"))
            item["evidence"] = deepcopy(cached_data.get("evidence", item.get("evidence", [])))
            item["attack_candidates"] = deepcopy(cached_data.get("attack_candidates", item.get("attack_candidates", [])))
            item["blocked"] = bool(cached_data.get("blocked", item.get("blocked", False)))
            item["final_msg"] = cached_data.get("final_msg", item.get("final_msg", ""))
            item["llm_output"] = deepcopy(cached_data.get("llm_output", item.get("llm_output", {})))

            item["cache_hit"] = True
            item["cached_result"] = {
                "cache_key": cached_data.get("cache_key"),
                "request_checksum": cached_data.get("request_checksum"),
                "cache_written_at": cached_data.get("cache_written_at"),
                "engine_version": cached_data.get("engine_version"),
            }
        else:
            # Cache MISS - mark for analysis
            item["cache_hit"] = False

    return state


def cache_save_node(state: SOCState) -> dict:
    """
    Save analyzed results to cache for future requests.
    Cache only after a final decision message is available.
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

        cache_key = _make_key(raw_request)
        now_iso = datetime.now(timezone.utc).isoformat()
        cache_data = {
            "cache_key": cache_key,
            "request_checksum": cache_key,
            "attack_type": item.get("attack_type"),
            "rule_score": item.get("rule_score"),
            "severity": item.get("severity"),
            "fast_decision": item.get("fast_decision"),
            "evidence": item.get("evidence"),
            "attack_candidates": item.get("attack_candidates"),
            "blocked": item.get("blocked"),
            "final_msg": item.get("final_msg"),
            "llm_output": _build_cached_llm_output(item),
            "engine_version": CACHE_ENGINE_VERSION,
            "cache_written_at": now_iso,
            "analysis_logged": True,
            "analysis_logged_at": now_iso,
        }

        # Save to cache backend
        cache_set(raw_request, cache_data)

        # Persist rich details in a dedicated append-only log file.
        append_analysis_log(cache_key, _build_analysis_log(state, item, index, cache_key))
    
    return state
