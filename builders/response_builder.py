from soc_state import SOCState
from datetime import datetime, timezone

# Attack type mapping to groups
ATTACK_GROUPS = {
    "SQL Injection": "sql",
    "Cross-Site Scripting": "xss",
    "Command Injection": "command",
    "Directory Traversal": "path_traversal",
    "Local File Inclusion": "lfi",
    "Server-Side Request Forgery": "ssrf",
    "Log Injection": "log_injection",
    "Unknown": "generic",
    "Normal": "generic",
}

def get_suggested_actions(fast_decision, blocked):
    """Generate suggested actions based on decision"""
    if blocked:
        return ["Block request", "Log attack for forensics", "Alert security team"]
    elif fast_decision == "REVIEW":
        return ["Review manually", "Log for monitoring", "Check user context"]
    elif fast_decision == "MONITOR":
        return ["Allow request", "Log for monitoring"]
    else:  # ALLOW
        return ["Allow request"]

def get_learning_note(attack_type, severity):
    """Generate security learning note"""
    notes = {
        "SQL Injection": "SQL injection attacks can compromise database integrity. Always use parameterized queries and input validation.",
        "Cross-Site Scripting": "XSS attacks can steal user sessions and credentials. Implement proper output encoding and Content Security Policy.",
        "Command Injection": "Command injection can lead to remote code execution. Never pass user input directly to system commands.",
        "Directory Traversal": "Path traversal attacks can expose sensitive files. Validate and sanitize all file path inputs.",
        "Local File Inclusion": "LFI attacks can read sensitive server files. Restrict file access and validate wrapper usage.",
        "Server-Side Request Forgery": "SSRF can expose internal services. Validate URLs and restrict outbound connections.",
        "Log Injection": "Log injection can corrupt audit trails. Sanitize all log inputs and use structured logging.",
        "Unknown": "Unknown patterns require careful analysis to determine legitimacy and potential risk.",
    }
    return notes.get(attack_type, "Review request context and user behavior to assess risk.")


def get_recommendation(attack_type):
    """Return a short preventive recommendation for the given attack type."""
    # Normalize attack_type to a consistent key for lookup
    normalized_attack_type = attack_type.replace(" ", "_").lower()

    recs = {
        "LFI": "Disallow dynamic includes based on user input and validate paths against a whitelist.",
        "XXE": "Disable XXE processing in XML parsers; validate and sanitize XML inputs.",
        "IDOR": "Implement proper authorization checks for all object references.",
        "Broken Auth": "Enforce strong password policies, multi-factor authentication, and secure session management.",
        "Sec Misconfig": "Regularly audit and harden system configurations; follow security best practices.",
        "Sensitive Data Exp": "Encrypt sensitive data at rest and in transit; implement strong access controls.",
        "Broken Access Control": "Implement least privilege principle; enforce robust access control mechanisms.",
        "SSTI": "Sanitize user input before rendering templates; use sandboxed template engines.",
        "Insufficient Logging": "Implement comprehensive logging, monitoring, and alerting for security events.",
        "Deserialization": "Avoid deserializing untrusted data; use secure serialization formats.",
        "SQL Injection": "Use parameterized queries or prepared statements to prevent SQL injection.",
        "Cross-Site Scripting": "Implement proper output encoding and a strong Content Security Policy (CSP).",
        "Command Injection": "Avoid executing OS commands with user-supplied input; use safer alternatives.",
        "Directory Traversal": "Validate and sanitize all file path inputs; use a whitelist of allowed paths.",
        "Local File Inclusion": "Disable dynamic file includes; validate and restrict file access to trusted sources.",
        "Server-Side Request Forgery": "Validate URLs, restrict outbound requests, and use a whitelist for allowed domains.",
        "Log Injection": "Sanitize all user-supplied input before logging to prevent log forging.",
    }
    # Normalize attack_type to match dictionary keys if necessary, though current keys are already capitalized.
    # For robustness, we can ensure consistent casing or handle variations.
    # Given the existing keys are title-cased, we'll assume attack_type comes in that format.
    # If attack_type could be lowercased or different, a mapping or .title()/.capitalize() might be needed.
    return recs.get(attack_type, "Consult security best practices for the specific attack type or general web application security.")

def get_observed_patterns(item):
    """Extract observed patterns from evidence"""
    patterns = []
    
    if item.get("attack_candidates"):
        for candidate in item["attack_candidates"][:3]:
            patterns.append({
                "pattern_name": candidate["type"],
                "description": f"Detected {candidate.get('rule_matches', 0)} rule matches with score {candidate['score']}",
                "severity": item["severity"],
                "rule_matches": candidate.get("rule_matches", 0)
            })
    
    if not patterns and item.get("evidence"):
        for ev in item["evidence"][:3]:
            patterns.append({
                "pattern_name": ev,
                "description": f"Pattern match detected: {ev}",
                "severity": item["severity"]
            })
    
    return patterns

def response_builder(state: SOCState) -> dict:
    responses = []

    for item in state["items"]:
        # Determine route and source
        used_llm = item["llm_output"] is not None and item["llm_output"].get("model")
        route = "slow" if used_llm else "fast"
        source = "llm_explainer" if used_llm else "rule_engine"
        
        # Determine event type
        if item["blocked"]:
            event_type = "fast_block" if route == "fast" else "slow_block"
        else:
            event_type = "slow_explanation" if route == "slow" else "fast_allow"
        
        # Map attack type to label
        attack_type = item["attack_type"]
        if attack_type in ["Unknown", "Normal"]:
            label = "Normal"
            attack_type_field = "none"
        else:
            label = attack_type
            attack_type_field = attack_type.lower().replace(" ", "_")
        
        # Calculate confidence (from LLM or rule score)
        rule_score = item["rule_score"]
        if used_llm and item["llm_output"].get("confidence"):
            confidence = item["llm_output"]["confidence"]
        elif rule_score >= 10:
            confidence = 0.95
        elif rule_score >= 5:
            confidence = 0.85
        elif rule_score >= 3:
            confidence = 0.6
        else:
            confidence = 0.4
        
        # Build response
        result = {
            "label": label,
            "attack_group": ATTACK_GROUPS.get(attack_type, "generic"),
            "attack_type": attack_type_field,
            "confidence": round(confidence, 2),
            "risk_score": int(rule_score),
            "severity": item["severity"],
            "evidence": item.get("evidence", []),
            "rag_context": item.get("rag_context", ""),
            "observed_patterns": get_observed_patterns(item),
            "suggested_actions": get_suggested_actions(item.get("fast_decision"), item["blocked"]),
            "route": route,
            "event_type": event_type,
            "source": source,
            "explanation": item["final_msg"] or f"Request analyzed with {source}",
            "hallucination_suspected": False,
            "hallucination_reasons": [],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Add LLM-specific fields if available
        if used_llm:
            result["llm_model"] = item["llm_output"].get("model")
            result["llm_reasoning"] = item["llm_output"].get("reasoning", "")
        
        responses.append(result)

    return {
        "result_json": {
            "results": responses,
            "flow_version": "capstone_http_analyzer.hybrid.v1",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    }
