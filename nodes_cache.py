"""Cache checking and saving nodes"""
from soc_state import SOCState
import hashlib


def _hash_request(request: str) -> str:
    """Generate hash for caching request"""
    return hashlib.md5(request.lower().encode()).hexdigest()


# Simple in-memory cache (in production, use Redis/Memcached)
REQUEST_CACHE = {}


def cache_check_node(state: SOCState) -> dict:
    """
    Check if request results are already cached.
    If cached, populate cache_hit=True and copy cached analysis.
    If not cached, set cache_hit=False and continue to rule engine.
    """
    for item in state.get("items", []):
        request_hash = _hash_request(item["raw_request"])
        
        if request_hash in REQUEST_CACHE:
            # Cache HIT - restore cached analysis
            cached_data = REQUEST_CACHE[request_hash]
            item["cache_hit"] = True
            item["attack_type"] = cached_data["attack_type"]
            item["rule_score"] = cached_data["rule_score"]
            item["severity"] = cached_data["severity"]
            item["fast_decision"] = cached_data["fast_decision"]
            item["evidence"] = cached_data["evidence"]
            item["attack_candidates"] = cached_data["attack_candidates"]
            item["blocked"] = cached_data["blocked"]
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
        # Skip if already cached
        request_hash = _hash_request(item["raw_request"])
        
        if request_hash not in REQUEST_CACHE:
            # Save to cache
            REQUEST_CACHE[request_hash] = {
                "attack_type": item.get("attack_type"),
                "rule_score": item.get("rule_score"),
                "severity": item.get("severity"),
                "fast_decision": item.get("fast_decision"),
                "evidence": item.get("evidence"),
                "attack_candidates": item.get("attack_candidates"),
                "blocked": item.get("blocked"),
            }
    
    return state
