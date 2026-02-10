from pathlib import Path
import sys
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import only what we need - avoid heavy dependencies like sentence_transformers
from langgraph.graph import StateGraph, END, START
from soc_state import SOCState


def build_graph():
    """Build the graph without importing heavy backends"""
    graph = StateGraph(SOCState)
    
    # Just add nodes without full implementation - we just want the structure
    def dummy_node(state):
        return state
    
    graph.add_node("decode", dummy_node)
    graph.add_node("cache_check", dummy_node)
    graph.add_node("rule_engine", dummy_node)
    graph.add_node("router", dummy_node)
    graph.add_node("save_cache", dummy_node)
    graph.add_node("llm_analyze", dummy_node)
    graph.add_node("build_response", dummy_node)
    
    # Add edges for cache_first architecture
    graph.add_edge(START, "decode")
    graph.add_edge("decode", "cache_check")
    graph.add_conditional_edges(
        "cache_check",
        lambda x: "response" if x.get("cache_hit") else "rule_engine",
        {"rule_engine": "rule_engine", "response": "build_response"}
    )
    graph.add_edge("rule_engine", "router")
    graph.add_conditional_edges(
        "router",
        lambda x: x.get("route", "llm_analyze"),
        {"fast": "save_cache", "slow": "llm_analyze"}
    )
    graph.add_edge("llm_analyze", "save_cache")
    graph.add_edge("save_cache", "build_response")
    graph.add_edge("build_response", END)
    
    return graph.compile()


def main() -> None:
    # Save to root artifacts folder, not scripts/artifacts
    out_dir = Path(__file__).parent.parent / "artifacts"
    out_dir.mkdir(exist_ok=True)

    graph_compiled = build_graph()
    graph = graph_compiled.get_graph()

    mermaid = graph.draw_mermaid()
    mermaid_path = out_dir / "langgraph.mmd"
    mermaid_path.write_text(mermaid, encoding="utf-8")

    png_path = out_dir / "langgraph.png"
    try:
        png_bytes = graph.draw_mermaid_png()
    except Exception as exc:
        print("Could not render PNG. Mermaid source saved to:", mermaid_path)
        print("Error:", exc)
        return

    png_path.write_bytes(png_bytes)
    print("Graph rendered to:", png_path)


if __name__ == "__main__":
    main()
