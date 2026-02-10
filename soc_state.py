from typing import TypedDict, List, Dict, Any


class SOCItem(TypedDict):
    id: str
    raw_request: str

    # ===== RULE ENGINE =====
    attack_type: str
    rule_score: float
    severity: str
    fast_decision: str
    evidence: Any
    attack_candidates: Any

    # ===== ROUTER =====
    blocked: bool

    # ===== CACHE / RAG =====
    cache_hit: bool
    cached_result: Dict[str, Any]
    rag_context: str

    # ===== LLM =====
    llm_output: Dict[str, Any]

    # ===== FINAL =====
    final_msg: str


class SOCState(TypedDict):
    # batch input (initial)
    requests: List[str]
    
    # decoded items
    items: List[SOCItem]

    # batch output (để dùng sau)
    results: List[SOCItem]
    
    # final formatted response
    result_json: Dict[str, Any]
