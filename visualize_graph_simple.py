"""Simple graph visualization without RAG backend imports"""
from pathlib import Path
from langgraph.graph import StateGraph, END, START
from soc_state import SOCState


def create_simple_graph():
    """Create graph structure without importing nodes that require RAG"""
    graph = StateGraph(SOCState)

    # Add nodes as stubs (structure only)
    def decode_node(state):
        return state

    def cache_check_node(state):
        state["cache_hit"] = False
        return state

    def rule_engine_node(state):
        return state

    def router_node(state):
        return state

    def llm_node(state):
        return state

    def cache_save_node(state):
        return state

    def response_node(state):
        return state

    # Add nodes
    graph.add_node("decode", decode_node)
    graph.add_node("cache_check", cache_check_node)
    graph.add_node("rule_engine", rule_engine_node)
    graph.add_node("router", router_node)
    graph.add_node("llm", llm_node)
    graph.add_node("cache_save", cache_save_node)
    graph.add_node("response", response_node)

    # Add edges
    graph.add_edge(START, "decode")
    graph.add_edge("decode", "cache_check")

    # Conditional: cache hit -> response, miss -> rule_engine
    graph.add_conditional_edges(
        "cache_check",
        lambda state: "response" if state.get("cache_hit") else "rule_engine",
        {"response": "response", "rule_engine": "rule_engine"},
    )

    graph.add_edge("rule_engine", "router")

    # Conditional: fast -> cache_save, slow -> llm
    graph.add_conditional_edges(
        "router",
        lambda state: "cache_save" if state.get("fast_decision") == "BLOCK" else "llm",
        {"cache_save": "cache_save", "llm": "llm"},
    )

    graph.add_edge("llm", "cache_save")
    graph.add_edge("cache_save", "response")
    graph.add_edge("response", END)

    return graph.compile()


def main():
    out_dir = Path("artifacts")
    out_dir.mkdir(exist_ok=True)

    print("Creating graph structure...")
    graph_compiled = create_simple_graph()
    
    # Get the underlying StateGraph
    graph = graph_compiled.get_graph()

    # Save Mermaid
    mermaid = graph.draw_mermaid()
    mermaid_path = out_dir / "langgraph.mmd"
    mermaid_path.write_text(mermaid, encoding="utf-8")
    print(f"✅ Saved: {mermaid_path}")

    # Try to save PNG
    png_path = out_dir / "langgraph.png"
    try:
        png_bytes = graph.draw_mermaid_png()
        png_path.write_bytes(png_bytes)
        print(f"✅ Saved: {png_path}")
    except Exception as exc:
        print(f"⚠️  PNG render failed (graphviz needed): {exc}")
        print(f"   Mermaid source available at: {mermaid_path}")

    print("\n" + "=" * 60)
    print("Graph structure:")
    print("=" * 60)
    print(mermaid)


if __name__ == "__main__":
    main()
