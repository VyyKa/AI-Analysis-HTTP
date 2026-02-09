from soc_state import SOCState
from cache_backend import cache_get
from rag_backend import vector_search, rag_list_parser


def cache_router_node(state: SOCState) -> SOCState:
    for item in state["items"]:
        # item đã BLOCK thì bỏ qua
        if item["blocked"]:
            continue

        query = item["raw_request"]

        # 1. Cache check
        cached = cache_get(query)
        if cached:
            item["cache_hit"] = True
            item["final_msg"] = cached
            continue

        # 2. Cache MISS → RAG
        search_results = vector_search(query)
        rag_context = rag_list_parser(search_results)

        item["cache_hit"] = False
        item["rag_context"] = rag_context

    return state
