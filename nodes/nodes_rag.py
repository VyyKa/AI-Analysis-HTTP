"""Node responsible for fetching RAG (Retrieval-Augmented Generation) context.

This is separated out so the flow graph can show an explicit rag step
instead of hiding it inside cache logic.  The node performs a vector search
and formats the results for the LLM; it executes on every request and the
result is not cached (fresh search each time).
"""
from soc_state import SOCState
from backends.rag_backend import vector_search, rag_list_parser


def rag_node(state: SOCState) -> SOCState:
    """Populate each item's ``rag_context`` field.

    ``rag_context`` is a plain string summarizing the top-k vector search
    results.  The vector search itself uses a remote service (Qdrant +
    HuggingFace embeddings) so we don't attempt to cache it locally.
    """
    for item in state.get("items", []):
        # Only fetch RAG for items that still need LLM processing
        if item.get("blocked") or item.get("cache_hit") or item.get("final_msg"):
            item["rag_context"] = item.get("rag_context", "")
            continue

        raw_request = item.get("raw_request", "")
        try:
            search_results = vector_search(raw_request)
            item["rag_context"] = rag_list_parser(search_results)
        except Exception:
            # Keep flow resilient if vector backend is unavailable
            item["rag_context"] = ""
    return state
