from soc_state import SOCState
from backends.llm_backend import llm_analyze, llm_bulk_analyze


def llm_node(state: SOCState) -> SOCState:
    # collect indices of items that require LLM
    indices = []
    queries = []
    contexts = []

    for idx, item in enumerate(state.get("items", [])):
        if item.get("blocked") or item.get("cache_hit") or item.get("final_msg"):
            continue
        indices.append(idx)
        queries.append(item.get("raw_request", ""))
        contexts.append(item.get("rag_context", ""))

    # no work to do
    if not indices:
        return state

    if len(queries) > 1:
        try:
            results = llm_bulk_analyze(queries, contexts)
        except Exception:
            results = [llm_analyze(q, c) for q, c in zip(queries, contexts)]
    else:
        results = [llm_analyze(queries[0], contexts[0])]

    # Guard against malformed bulk output length
    if len(results) != len(indices):
        results = [llm_analyze(q, c) for q, c in zip(queries, contexts)]

    for idx, result in zip(indices, results):
        item = state["items"][idx]
        item["llm_output"] = result
        analysis_data = result.get("analysis", {})

        if isinstance(analysis_data, dict):
            threat_score = analysis_data.get("threat_score", 0)
            attack_type = analysis_data.get("attack_type", "Unknown")
            justification = analysis_data.get("justification", "")
            action = analysis_data.get("action", "REVIEW").upper()
            item["attack_type"] = attack_type
            item["final_msg"] = f"[LLM] {justification} (Score: {threat_score}, Action: {action})"
            if action == "BLOCK" or (isinstance(threat_score, (int, float)) and threat_score >= 6):
                item["blocked"] = True
                item["fast_decision"] = "BLOCK"
        else:
            item["final_msg"] = str(analysis_data)
            verdict = str(analysis_data).lower()
            if "malicious" in verdict or "attack" in verdict:
                item["blocked"] = True
                item["fast_decision"] = "BLOCK"

    return state
