import uuid
from soc_state import SOCState, SOCItem


def batch_decoder(input_data) -> SOCState:
    items: list[SOCItem] = []

    # Case 1: string đơn (legacy)
    if isinstance(input_data, str):
        items.append({
            "id": str(uuid.uuid4()),
            "raw_request": input_data,
        })

    # Case 2: list[str]
    elif isinstance(input_data, list):
        for r in input_data:
            items.append({
                "id": str(uuid.uuid4()),
                "raw_request": str(r),
            })

    # Case 3: dict { requests: [...] }
    elif isinstance(input_data, dict) and "requests" in input_data:
        for r in input_data["requests"]:
            items.append({
                "id": str(uuid.uuid4()),
                "raw_request": str(r),
            })

    else:
        raise ValueError("Unsupported input format")

    # Khởi tạo đầy đủ field cho mỗi item
    for it in items:
        it.update({
            "attack_type": "",
            "rule_score": 0.0,
            "severity": "",
            "fast_decision": "",
            "evidence": None,
            "attack_candidates": None,
            "blocked": False,
            "cache_hit": False,
            "rag_context": "",
            "llm_output": {},
            "final_msg": "",
        })

    return {
        "items": items,
        "results": [],
    }
