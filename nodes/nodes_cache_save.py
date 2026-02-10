"""Node to save analysis results to cache"""

from soc_state import SOCState
from backends.cache_backend import cache_set


def cache_save_node(state: SOCState) -> SOCState:
    """Save successful analysis results to cache for faster future lookups"""
    for item in state["items"]:
        # Skip if already from cache
        if item.get("cache_hit"):
            continue

        # Skip if no analysis done yet
        if not item.get("final_msg"):
            continue

        query = item["raw_request"]
        
        # Build result object to cache
        result_obj = {
            "final_msg": item["final_msg"],
            "llm_output": item.get("llm_output"),
            "attack_type": item.get("attack_type"),
            "severity": item.get("severity"),
            "rule_score": item.get("rule_score"),
            "evidence": item.get("evidence"),
        }
        
        # Save to cache (including blocked items)
        cache_set(query, result_obj)

    return state
