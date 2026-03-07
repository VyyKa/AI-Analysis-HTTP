from soc_state import SOCState


def router_node(state: SOCState) -> SOCState:
    """
    Intelligent routing node:
    1. If rule_score = 0 and no patterns found, ALLOW immediately (don't send to LLM)
    2. If high confidence block (score >= 5), mark BLOCKED
    3. If low uncertainty (0 < score < 5), send to slow path (RAG+LLM)
    """
    for item in state["items"]:
        rule_score = item.get("rule_score", 0)
        severity = item.get("severity", "Info")
        evidence = item.get("evidence", [])
        
        # RULE 1: score=0 and no patterns found -> ALLOW immediately (avoid LLM for generic text)
        if rule_score == 0 and (not evidence or evidence == ["no_pattern_match"]):
            item["blocked"] = False
            item["fast_decision"] = "ALLOW"
            item["final_msg"] = (
                f"[FAST_ALLOW] Generic/Benign text | "
                f"Score={rule_score} | Severity={severity}"
            )
        # RULE 2: High confidence attack (score >= 5)
        elif rule_score >= 5:
            item["blocked"] = True
            item["final_msg"] = (
                f"[BLOCKED] {item['attack_type']} | "
                f"Score={rule_score} | Severity={severity}"
            )
        # RULE 3: Moderate uncertainty (1 <= score < 5) -> send to slow path
        elif 1 <= rule_score < 5:
            # Leave final_msg empty to allow RAG+LLM to handle
            pass
        # RULE 4: Explicit ALLOW by rules
        elif item.get("fast_decision") == "ALLOW":
            item["final_msg"] = (
                f"[ALLOW] {item.get('attack_type', 'Normal')} | "
                f"Score={rule_score} | Severity={severity}"
            )
        else:
            # Default: REVIEW path
            pass

    return state
