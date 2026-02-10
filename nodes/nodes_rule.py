from soc_state import SOCState
from backends.rule_engine import analyze_request


def rule_engine_node(state: SOCState) -> SOCState:
    for item in state["items"]:
        r = analyze_request(item["raw_request"])

        item["attack_type"] = r["attack_type"]
        item["rule_score"] = r["rule_score"]
        item["severity"] = r["severity"]
        item["fast_decision"] = r["fast_decision"]
        item["evidence"] = r["evidence"]
        item["attack_candidates"] = r["attack_candidates"]

        # Block if decision is BLOCK
        if r["fast_decision"] == "BLOCK":
            item["blocked"] = True
        # REVIEW and MONITOR will continue to LLM analysis
        # ALLOW also continues (though unlikely with current logic)

    return state
