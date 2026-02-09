from langgraph.graph import StateGraph, END
from soc_state import SOCState

from batch_decoder import batch_decoder
from nodes_rule import rule_engine_node
from nodes_router import router_node
from nodes_cache import cache_router_node
from nodes_llm import llm_node
from nodes_response import response_node

graph = StateGraph(SOCState)

graph.add_node("decode", lambda data: batch_decoder(data.get("requests", [])))
graph.add_node("rule", rule_engine_node)
graph.add_node("router", router_node)
graph.add_node("cache", cache_router_node)
graph.add_node("llm", llm_node)
graph.add_node("response", response_node)

graph.set_entry_point("decode")
graph.add_edge("decode", "rule")
graph.add_edge("rule", "router")
graph.add_edge("router", "cache")
graph.add_edge("cache", "llm")
graph.add_edge("llm", "response")
graph.add_edge("response", END)

soc_app = graph.compile()
