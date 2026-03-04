from soc_state import SOCState


def router_node(state: SOCState) -> SOCState:
    for item in state["items"]:
        if item["blocked"]:
            # BLOCK sớm – giống BlockerNode
            item["final_msg"] = (
                f"[BLOCKED] {item['attack_type']} | "
                f"Score={item['rule_score']} | "
                f"Severity={item['severity']}"
            )
        elif item.get("fast_decision") == "ALLOW":
            # ALLOW by rules should finish on fast path
            item["final_msg"] = (
                f"[ALLOW] {item.get('attack_type', 'Normal')} | "
                f"Score={item.get('rule_score', 0)} | "
                f"Severity={item.get('severity', 'Info')}"
            )
        else:
            # REVIEW / MONITOR / ALLOW
            # để trống final_msg, đi tiếp cache / rag / llm
            pass

    return state
