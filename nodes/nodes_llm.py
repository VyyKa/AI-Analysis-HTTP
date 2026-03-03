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
        
        # Extract fields from the new JSON format
        analysis_data = result.get("analysis", {})
        
        if isinstance(analysis_data, dict):
            threat_score = analysis_data.get("threat_score", 0)
            attack_type = analysis_data.get("attack_type", "Unknown")
            justification = analysis_data.get("justification", "")
            action = analysis_data.get("action", "REVIEW").upper()
            
            # Update item properties based on LLM profound analysis
            item["attack_type"] = attack_type
            item["final_msg"] = f"[LLM] {justification} (Score: {threat_score}, Action: {action})"
            
            # Phá lệ, nếu Action là BLOCK, hoặc Điểm >= 6 thì Block
            if action == "BLOCK" or (isinstance(threat_score, (int, float)) and threat_score >= 6):
                item["blocked"] = True
                item["fast_decision"] = "BLOCK"
        else:
            # Fallback if something went wrong and it's still a string
            item["final_msg"] = str(analysis_data)
            verdict = str(analysis_data).lower()
            if "malicious" in verdict or "attack" in verdict:
                item["blocked"] = True
                item["fast_decision"] = "BLOCK"

    return state
