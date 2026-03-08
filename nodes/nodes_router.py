import os

from soc_state import SOCState


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


FAST_BLOCK_THRESHOLD = _env_int("FAST_BLOCK_THRESHOLD", 10)


def router_node(state: SOCState) -> SOCState:
    """
    Intelligent routing node:
    1. Respect explicit ALLOW/BLOCK from rule engine
    2. Enforce fast BLOCK only for very high-confidence score
    3. Send most suspicious traffic to slow path (LLM-first)
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
        # RULE 2: Only keep ultra-high confidence blocks on fast path
        elif (fast_decision == "BLOCK" and rule_score >= FAST_BLOCK_THRESHOLD) or rule_score >= FAST_BLOCK_THRESHOLD:
            item["blocked"] = True
            item["fast_decision"] = "BLOCK"
            item["final_msg"] = (
                f"[BLOCKED] {item['attack_type']} | "
                f"Score={rule_score} | Severity={severity}"
            )
        # RULE 3: REVIEW/MONITOR and moderate BLOCK signals go to slow path
        elif fast_decision in ("BLOCK", "REVIEW", "MONITOR"):
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
            # Keep final_msg empty so graph routes through slow path.
        # RULE 4: Unknown/empty fast decision should not be fast-allowed
        else:
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
            # Keep final_msg empty so graph routes through slow path.

    return state
