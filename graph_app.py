from langgraph.graph import StateGraph, END
from soc_state import SOCState

from backends.batch_decoder import batch_decoder
from nodes.nodes_rule import rule_engine_node
from nodes.nodes_router import router_node
from nodes.nodes_cache import cache_router_node
from nodes.nodes_cache_save import cache_save_node
from nodes.nodes_llm import llm_node
from nodes.nodes_response import response_node

graph = StateGraph(SOCState)

graph.add_node("decode", lambda data: batch_decoder(data.get("requests", [])))
graph.add_node("rule", rule_engine_node)
graph.add_node("router", router_node)
graph.add_node("cache", cache_router_node)
graph.add_node("llm", llm_node)
graph.add_node("cache_save", cache_save_node)
graph.add_node("response", response_node)


def route_after_rule(state: SOCState) -> str:
	# Fast path only when all items are blocked by rules.
	if state.get("items") and all(item.get("blocked") for item in state["items"]):
		return "fast"
	return "slow"

graph.set_entry_point("decode")
graph.add_edge("decode", "rule")
graph.add_edge("rule", "router")
graph.add_conditional_edges(
	"router",
	route_after_rule,
	{
        "fast": "cache_save",  # Fast path: skip slow analysis, go to save & response
        "slow": "cache",       # Slow path: check cache, then LLM if needed
    },
)
graph.add_edge("cache", "llm")
graph.add_edge("llm", "cache_save")
graph.add_edge("cache_save", "response")
graph.add_edge("response", END)

soc_app = graph.compile()
