"""Mock LLM backend for testing without API"""

def llm_analyze(query: str, rag_context: str) -> dict:
    """Mock LLM that returns canned response"""
    
    # Simple heuristic
    keywords = ["select", "union", "script", "alert", "..", "etc/passwd"]
    has_attack = any(kw in query.lower() for kw in keywords)
    
    if has_attack:
        verdict = "Suspicious patterns detected in request. Recommend review."
    else:
        verdict = "Benign request – no malicious intent detected."
    
    return {
        "analysis": verdict,        
        "model": "mock-llm",
    }
