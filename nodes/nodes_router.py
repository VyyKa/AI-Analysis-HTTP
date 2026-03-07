from soc_state import SOCState


def router_node(state: SOCState) -> SOCState:
    """
    Intelligent routing node:
    1. Respect explicit ALLOW/BLOCK from rule engine
    2. Enforce fast BLOCK for high-confidence score (>= 5)
    3. Keep REVIEW/MONITOR/unknown decisions on slow path
    """
    for item in state["items"]:
        rule_score = item.get("rule_score", 0)
        severity = item.get("severity", "Info")
        fast_decision = str(item.get("fast_decision", "")).upper()
        
        # RULE 1: Explicit ALLOW from rules (safe pattern / normal HTTP heuristic)
        if fast_decision == "ALLOW":
            item["blocked"] = False
            item["final_msg"] = (
                f"[ALLOW] {item.get('attack_type', 'Normal')} | "
                f"Score={rule_score} | Severity={severity}"
            )
        # RULE 2: High confidence attack
        elif fast_decision == "BLOCK" or rule_score >= 5:
            item["blocked"] = True
            item["fast_decision"] = "BLOCK"
            item["final_msg"] = (
                f"[BLOCKED] {item['attack_type']} | "
                f"Score={rule_score} | Severity={severity}"
            )
        # RULE 3: REVIEW/MONITOR keep going to slow path
        elif fast_decision in ("REVIEW", "MONITOR"):
            item["blocked"] = False
            # Keep final_msg empty so graph routes through slow path.
        # RULE 4: Unknown/empty fast decision should not be fast-allowed
        else:
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
            # Keep final_msg empty so graph routes through slow path.

    return state
