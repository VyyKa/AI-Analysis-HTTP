"""Node responsible for fetching RAG (Retrieval-Augmented Generation) context.

This is separated out so the flow graph can show an explicit rag step
instead of hiding it inside cache logic.  The node performs a vector search
and formats the results for the LLM; it executes on every request and the
result is not cached (fresh search each time).
"""
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from soc_state import SOCState
from backends.rag_backend import vector_search, rag_list_parser


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _fetch_rag_context(raw_request: str) -> str:
    try:
        search_results = vector_search(raw_request)
        return rag_list_parser(search_results)
    except Exception:
        return ""


def rag_node(state: SOCState) -> SOCState:
    """Populate each item's ``rag_context`` field.

    ``rag_context`` is a plain string summarizing the top-k vector search
    results.  The vector search itself uses a remote service (Qdrant +
    HuggingFace embeddings) so we don't attempt to cache it locally.
    """
    items = state.get("items", [])
    pending_by_request: dict[str, list[int]] = {}

    for idx, item in enumerate(items):
        # Only fetch RAG for items that still need LLM processing
        if item.get("blocked") or item.get("cache_hit") or item.get("final_msg"):
            item["rag_context"] = item.get("rag_context", "")
            continue

        raw_request = item.get("raw_request", "")
        pending_by_request.setdefault(raw_request, []).append(idx)

    if not pending_by_request:
        return state

    contexts_by_request: dict[str, str] = {}
    unique_requests = list(pending_by_request.keys())

    if len(unique_requests) == 1:
        request = unique_requests[0]
        contexts_by_request[request] = _fetch_rag_context(request)
    else:
        worker_cap = _env_int("RAG_MAX_WORKERS", 6)
        max_workers = min(worker_cap, len(unique_requests))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_request = {
                executor.submit(_fetch_rag_context, request): request
                for request in unique_requests
            }
            for future in as_completed(future_to_request):
                request = future_to_request[future]
                try:
                    contexts_by_request[request] = future.result()
                except Exception:
                    contexts_by_request[request] = ""

    for raw_request, indices in pending_by_request.items():
        rag_context = contexts_by_request.get(raw_request, "")
        for idx in indices:
            items[idx]["rag_context"] = rag_context

    return state
