import os
import re
from html import unescape
from urllib.parse import unquote

from soc_state import SOCState
from backends.llm_backend import llm_analyze, llm_bulk_analyze


ATTACK_TYPE_CANONICAL = {
    "xss": "Cross-Site Scripting",
    "path traversal": "Directory Traversal",
    "directory traversal": "Directory Traversal",
    "lfi": "Local File Inclusion",
    "ssrf": "Server-Side Request Forgery",
    "sqli": "SQL Injection",
}


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


LLM_BLOCK_MIN_THREAT = _env_int("LLM_BLOCK_MIN_THREAT", 6)
# Keep rule-first safety for medium-confidence detections even when LLM says ALLOW.
RULE_ALLOW_OVERRIDE_REVIEW_SCORE = _env_int("RULE_ALLOW_OVERRIDE_REVIEW_SCORE", 4)


ATTACK_HINT_PATTERNS = [
    r"<\s*[a-z0-9:_-]*script\b",
    r"</\s*[a-z0-9:_-]*script\s*>",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"on[a-z]{3,20}\s*=",
    r"alert\s*\(",
    r"document\.cookie",
    r"\beval\s*\(",
    r"/etc/(?:passwd|shadow|sudoers|hosts|crontab|group)\b",
    r"\.\./",
    r"\bunion\b\s+select\b",
    r"\bor\b\s+\d+\s*=\s*\d+",
]


BASE64_OR_HEX_MARKER = re.compile(
    r"(?:[A-Za-z0-9+/]{20,}={0,2})|(?:0x[0-9a-fA-F]{6,})"
)


def _decoded_views(raw_request: str) -> list[str]:
    """Generate lowercased decoded variants to catch encoded attack evidence."""
    base = str(raw_request or "")
    views = [base]
    current = base

    for _ in range(2):
        percent_decoded = unquote(current)
        html_decoded = unescape(percent_decoded)

        if percent_decoded not in views:
            views.append(percent_decoded)
        if html_decoded not in views:
            views.append(html_decoded)

        if percent_decoded == current and html_decoded == current:
            break
        current = percent_decoded

    return [v.lower() for v in views]


def _has_attack_markers(raw_request: str) -> bool:
    for view in _decoded_views(raw_request):
        for pattern in ATTACK_HINT_PATTERNS:
            if re.search(pattern, view, flags=re.IGNORECASE):
                return True
    return False


def _bulk_analyze_chunked(queries: list[str], contexts: list[str]) -> list[dict]:
    if not queries:
        return []

    chunk_size = _env_int("LLM_BULK_CHUNK_SIZE", 12)
    results: list[dict] = []

    for start in range(0, len(queries), chunk_size):
        q_chunk = queries[start:start + chunk_size]
        c_chunk = contexts[start:start + chunk_size]

        if len(q_chunk) == 1:
            chunk_results = [llm_analyze(q_chunk[0], c_chunk[0])]
        else:
            try:
                chunk_results = llm_bulk_analyze(q_chunk, c_chunk)
            except Exception:
                chunk_results = [llm_analyze(q, c) for q, c in zip(q_chunk, c_chunk)]

        if len(chunk_results) != len(q_chunk):
            chunk_results = [llm_analyze(q, c) for q, c in zip(q_chunk, c_chunk)]

        results.extend(chunk_results)

    return results


def _detect_hallucination(item: dict, analysis_data: dict) -> bool:
    """
    Detect if LLM is hallucinating about attacks that don't exist in the actual request.
    
    Heuristics:
    1. threat_score >= 6 but rule_score = 0 (rule engine sees nothing suspicious)
    2. LLM found attack but request is very short/generic (< 10 chars)
    3. LLM justification references payload format not in actual request
    """
    threat_score = analysis_data.get("threat_score", 0)
    rule_score = item.get("rule_score", 0)
    raw_request = item.get("raw_request", "").strip()
    justification = str(analysis_data.get("justification", "")).lower()
    
    # Flag 1: High threat score but rule engine found nothing.
    # Keep LLM finding if request still contains clear attack signals
    # after URL/HTML decoding (encoded attacks are common bypasses).
    if threat_score >= 6 and rule_score == 0:
        if not _has_attack_markers(raw_request):
            return True
    
    # Flag 2: Request is very short/generic but LLM thinks it's an attack
    if len(raw_request) <= 10 and threat_score >= 5:
        return True
    
    # Flag 3: LLM claims base64/hex decoding, but request has no such markers.
    if "base64" in justification or "hex" in justification:
        if not any(BASE64_OR_HEX_MARKER.search(view) for view in _decoded_views(raw_request)):
            return True
    
    return False


def _canonicalize_attack_type(value: object) -> str:
    raw_type = str(value or "").strip()
    if not raw_type:
        return "Unknown"
    return ATTACK_TYPE_CANONICAL.get(raw_type.lower(), raw_type)


def _is_specific_attack_type(value: str) -> bool:
    return value.lower() not in {"", "unknown", "normal", "benign", "none"}


def _normalize_action(value: object) -> str:
    raw = str(value or "").strip().upper()
    if raw in {"ALLOW", "REVIEW", "BLOCK"}:
        return raw
    if "BLOCK" in raw or "DENY" in raw or "REJECT" in raw:
        return "BLOCK"
    if "ALLOW" in raw or "PASS" in raw:
        return "ALLOW"
    if "REVIEW" in raw or "MONITOR" in raw or "CHECK" in raw:
        return "REVIEW"
    return "REVIEW"


def _merge_attack_type(item: dict, llm_attack_type: object) -> str:
    """
    Prefer deterministic rule-engine labels when rule confidence is non-trivial.
    This prevents LLM from downgrading known attack patterns to "Benign".
    """
    rule_score = item.get("rule_score", 0)
    rule_attack_type = _canonicalize_attack_type(item.get("attack_type", "Unknown"))
    llm_attack = _canonicalize_attack_type(llm_attack_type)

    if isinstance(rule_score, (int, float)) and rule_score >= 3 and _is_specific_attack_type(rule_attack_type):
        if not _is_specific_attack_type(llm_attack):
            return rule_attack_type
        if llm_attack.lower() != rule_attack_type.lower():
            return rule_attack_type

    return llm_attack


def _apply_llm_result(item: dict, result: dict) -> None:
    item["llm_output"] = result
    analysis_data = result.get("analysis", {})
    model_name = str(result.get("model", ""))
    llm_fallback = "(fallback)" in model_name.lower()

    if isinstance(analysis_data, dict):
        threat_score = analysis_data.get("threat_score", 0)
        attack_type = _merge_attack_type(item, analysis_data.get("attack_type", "Unknown"))
        justification = analysis_data.get("justification", "")
        action = _normalize_action(analysis_data.get("action", "REVIEW"))
        item["attack_type"] = attack_type
        item["final_msg"] = f"[LLM] {justification} (Score: {threat_score}, Action: {action})"

        # If provider is unavailable and fallback verdict is used, avoid auto-allowing suspicious traffic.
        rule_score = item.get("rule_score", 0)
        if llm_fallback and isinstance(rule_score, (int, float)) and rule_score >= 5:
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
            item["final_msg"] = (
                f"[REVIEW] LLM fallback active and rule_score={rule_score}. "
                "Requires manual review."
            )
            return
        
        # Check for hallucination
        hallucinated = _detect_hallucination(item, analysis_data)
        item["hallucination_suspected"] = hallucinated
        
        if hallucinated:
            # Downgrade hallucinated findings to ALLOW
            item["blocked"] = False
            item["fast_decision"] = "ALLOW"
            item["final_msg"] = f"[HALLUCINATION_DETECTED] LLM made unfounded claim: {justification}. Marking as ALLOW."
        elif action == "BLOCK" and isinstance(threat_score, (int, float)) and threat_score >= LLM_BLOCK_MIN_THREAT:
            # Only BLOCK if both action=BLOCK AND threat_score is significantly high
            item["blocked"] = True
            item["fast_decision"] = "BLOCK"
        elif action == "BLOCK" and isinstance(threat_score, (int, float)) and threat_score < LLM_BLOCK_MIN_THREAT:
            # BLOCK action without sufficient threat score -> suspicious, demote to REVIEW
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
            item["final_msg"] = f"[REVIEW] LLM suggested block but score is low ({threat_score}). Requires manual review."
        elif action == "ALLOW":
            item["blocked"] = False
            if isinstance(rule_score, (int, float)) and rule_score >= RULE_ALLOW_OVERRIDE_REVIEW_SCORE and _is_specific_attack_type(attack_type):
                # Keep high-scoring rule hits in manual review even if LLM says ALLOW.
                item["fast_decision"] = "REVIEW"
                item["final_msg"] = (
                    f"[REVIEW] LLM suggested ALLOW but rule_score={rule_score} for {attack_type}. "
                    "Requires manual review."
                )
            else:
                item["fast_decision"] = "ALLOW"
        elif action == "REVIEW":
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
        else:
            item["blocked"] = False
            item["fast_decision"] = "REVIEW"
    else:
        item["final_msg"] = str(analysis_data)
        item["hallucination_suspected"] = False
        verdict = str(analysis_data).lower()
        if "malicious" in verdict or "attack" in verdict:
            item["blocked"] = True
            item["fast_decision"] = "BLOCK"


def llm_node(state: SOCState) -> SOCState:
    # collect indices of items that require LLM, deduplicated by (query, rag_context)
    indices_by_signature: dict[tuple[str, str], list[int]] = {}

    for idx, item in enumerate(state.get("items", [])):
        if item.get("blocked") or item.get("cache_hit") or item.get("final_msg"):
            continue
        signature = (item.get("raw_request", ""), item.get("rag_context", ""))
        indices_by_signature.setdefault(signature, []).append(idx)

    # no work to do
    if not indices_by_signature:
        return state

    signatures = list(indices_by_signature.keys())
    unique_queries = [sig[0] for sig in signatures]
    unique_contexts = [sig[1] for sig in signatures]

    if len(signatures) == 1:
        unique_results = [llm_analyze(unique_queries[0], unique_contexts[0])]
    else:
        unique_results = _bulk_analyze_chunked(unique_queries, unique_contexts)

    if len(unique_results) != len(signatures):
        unique_results = [llm_analyze(q, c) for q, c in zip(unique_queries, unique_contexts)]

    for signature, result in zip(signatures, unique_results):
        for idx in indices_by_signature[signature]:
            _apply_llm_result(state["items"][idx], result)

    return state
