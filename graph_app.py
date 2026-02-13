from langgraph.graph import StateGraph, END, START
from soc_state import SOCState
from backends.batch_decoder import batch_decoder
from nodes.nodes_cache import cache_check_node, cache_save_node
from nodes.nodes_rule import rule_engine_node
from nodes.nodes_router import router_node
from nodes.nodes_llm import llm_node
from nodes.nodes_response import response_node

graph = StateGraph(SOCState)

# Nodes
graph.add_node("decode", lambda data: batch_decoder(data.get("requests", [])))
graph.add_node("cache", cache_check_node)        # Early cache check
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
    """After rule: fast path (blocked) or slow path (needs LLM)."""
    if state.get("items") and all(item.get("blocked") for item in state["items"]):
        return "fast"
    return "slow"

# Flow: decode → cache_check → {hit: response} | {miss: rule → router → {fast|slow}}
graph.set_entry_point("decode")
graph.add_edge("decode", "cache")

graph.add_conditional_edges(
    "cache",
    route_cache_hit,
    {
        "cache_hit": "cache_save",      # Cached, save & response
        "cache_miss": "rule",            # Not cached, analyze
    },
)

graph.add_edge("rule", "router")
graph.add_conditional_edges(
    "router",
    route_after_rule,
    {
        "fast": "cache_save",            # Blocked, save & response
        "slow": "llm",                   # Needs LLM analysis
    },
)

graph.add_edge("llm", "cache_save")
graph.add_edge("cache_save", "response")
graph.add_edge("response", END)

soc_app = graph.compile()
