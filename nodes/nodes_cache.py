from soc_state import SOCState
from backends.cache_backend import cache_get
from backends.rag_backend import vector_search, rag_list_parser


def cache_router_node(state: SOCState) -> SOCState:
    """Check cache and load RAG context if cache miss"""
    for item in state["items"]:
        # item đã BLOCK thì bỏ qua
        if item["blocked"]:
            continue

        query = item["raw_request"]

        # 1. Cache check
        cached_result = cache_get(query)
        if cached_result:
            item["cache_hit"] = True
            item["cached_result"] = cached_result
            # Copy cached analysis to item
            item["llm_output"] = cached_result.get("llm_output")
            item["final_msg"] = cached_result.get("final_msg")
            continue

        # 2. Cache MISS → RAG
        search_results = vector_search(query)
        rag_context = rag_list_parser(search_results)

        item["cache_hit"] = False
        item["rag_context"] = rag_context

    return state
