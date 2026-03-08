from langgraph.graph import StateGraph, END, START
from soc_state import SOCState
from backends.batch_decoder import batch_decoder
from nodes.nodes_rag import rag_node
from nodes.nodes_cache import cache_check_node, cache_save_node
from nodes.nodes_rule import rule_engine_node
from nodes.nodes_router import router_node
from nodes.nodes_llm import llm_node
from nodes.nodes_response import response_node

graph = StateGraph(SOCState)

# Nodes
graph.add_node("decode", lambda data: batch_decoder(data.get("requests", [])))
graph.add_node("rag", rag_node)                # Compute retrieval context (RAG)
graph.add_node("cache", cache_check_node)     # Early cache check (now after rag)
graph.add_node("rule", rule_engine_node)
graph.add_node("router", router_node)
graph.add_node("llm", llm_node)
graph.add_node("cache_save", cache_save_node)
graph.add_node("response", response_node)

# Routing functions
def route_cache_hit(state: SOCState) -> str:
    """If cache hit, skip all analysis. If miss, go to rule engine."""
    if state.get("items") and all(item.get("cache_hit") for item in state["items"]):
        return "cache_hit"  # All cached, go to response
    return "cache_miss"    # Not cached, do analysis

def route_after_rule(state: SOCState) -> str:
    """After rule: choose slow path only if any item still needs LLM analysis."""
    items = state.get("items", [])
    if not items:
        return "fast"

    needs_slow = any(
        (not item.get("blocked"))
        and (not item.get("cache_hit"))
        and (not item.get("final_msg"))
        and (item.get("fast_decision") not in ("ALLOW", "BLOCK"))
        for item in items
    )
    return "slow" if needs_slow else "fast"

# Flow: decode → cache_check → {hit: response} | {miss: rule → router → {fast|slow → rag → llm}}
graph.set_entry_point("decode")
graph.add_edge("decode", "cache")

graph.add_conditional_edges(
    "cache",
    route_cache_hit,
    {
        "cache_hit": "response",      # Cached, return response directly
        "cache_miss": "rule",            # Not cached, analyze
    },
)

graph.add_edge("rule", "router")
graph.add_conditional_edges(
    "router",
    route_after_rule,
    {
        "fast": "response",            # Fast decision path
        "slow": "rag",                   # Slow path should fetch RAG
    },
)

# slow path connects rag → llm → response
graph.add_edge("rag", "llm")
graph.add_edge("llm", "response")

# cache save runs after response to persist minimal cache + detailed JSONL logs
graph.add_edge("response", "cache_save")
graph.add_edge("cache_save", END)

soc_app = graph.compile()
