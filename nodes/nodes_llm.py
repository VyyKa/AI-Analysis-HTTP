from soc_state import SOCState
from backends.llm_backend import llm_analyze


def llm_node(state: SOCState) -> SOCState:
    for item in state["items"]:
        if item["blocked"]:
            continue

        if item["cache_hit"]:
            continue

        # Chỉ LLM cho item chưa có final_msg
        if item["final_msg"]:
            continue

        result = llm_analyze(
            query=item["raw_request"],
            rag_context=item["rag_context"]
        )

        item["llm_output"] = result
        item["final_msg"] = result["analysis"]

        # Nếu LLM phát hiện malicious, tự động block
        verdict = result["analysis"].lower()
        if "malicious request detected" in verdict or "script injection" in verdict or "attack" in verdict:
            item["blocked"] = True
            item["fast_decision"] = "BLOCK"

    return state
