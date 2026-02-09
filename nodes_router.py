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
        else:
            # REVIEW / MONITOR / ALLOW
            # để trống final_msg, đi tiếp cache / rag / llm
            pass

    return state
