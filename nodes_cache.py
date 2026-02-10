"""Cache checking and saving nodes"""
from soc_state import SOCState
from backends.cache_backend import cache_get, cache_set


def cache_check_node(state: SOCState) -> dict:
    """
    Check if request results are already cached.
    If cached, populate cache_hit=True and copy cached analysis.
    If not cached, set cache_hit=False and continue to rule engine.
    """
    for item in state.get("items", []):
        raw_request = item["raw_request"]
        
        # Check cache using backend
        cached_data = cache_get(raw_request)
        
        if cached_data:
            # Cache HIT - restore cached analysis
            item["cache_hit"] = True
            item["attack_type"] = cached_data.get("attack_type")
            item["rule_score"] = cached_data.get("rule_score")
            item["severity"] = cached_data.get("severity")
            item["fast_decision"] = cached_data.get("fast_decision")
            item["evidence"] = cached_data.get("evidence")
            item["attack_candidates"] = cached_data.get("attack_candidates")
            item["blocked"] = cached_data.get("blocked")
            item["final_msg"] = cached_data.get("final_msg")
            item["llm_output"] = cached_data.get("llm_output")
        else:
            # Cache MISS - mark for analysis
            item["cache_hit"] = False
    
    return state


def cache_save_node(state: SOCState) -> dict:
    """
    Save analyzed results to cache for future requests.
    Only cache after full analysis (rule + LLM).
    """
    for item in state.get("items", []):
        raw_request = item["raw_request"]
        
        # Check if already exists in cache
        if not cache_get(raw_request):
            # Build cache data
            cache_data = {
                "attack_type": item.get("attack_type"),
                "rule_score": item.get("rule_score"),
                "severity": item.get("severity"),
                "fast_decision": item.get("fast_decision"),
                "evidence": item.get("evidence"),
                "attack_candidates": item.get("attack_candidates"),
                "blocked": item.get("blocked"),
                "final_msg": item.get("final_msg"),
                "llm_output": item.get("llm_output"),
            }
            
            # Save to cache backend
            cache_set(raw_request, cache_data)
    
    return state
