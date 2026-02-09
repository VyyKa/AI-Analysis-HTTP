# Response Format Documentation

## Overview
This document describes the enhanced response format for the LangChain SOC Analyzer, aligned with the target system structure.

## Response Structure

### Top-Level Format
```json
{
  "result_json": {
    "results": [...],          // Array of analysis results
    "flow_version": "string",  // Version identifier
    "generated_at": "ISO8601"  // Overall generation timestamp
  }
}
```

### Result Object Fields

#### Core Classification
| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `label` | string | Human-readable attack label or "Normal" | "SQL Injection", "Normal" |
| `attack_group` | string | Attack category grouping | "sql", "xss", "command", "generic" |
| `attack_type` | string | Normalized attack type identifier | "sql_injection", "none" |
| `confidence` | float | Detection confidence (0.0-1.0) | 0.95 |
| `risk_score` | int | OWASP CRS anomaly score | 10 |
| `severity` | string | Threat severity level | "CRITICAL", "ERROR", "WARNING", "NOTICE", "Low" |

#### Evidence & Analysis
| Field | Type | Description |
|-------|------|-------------|
| `evidence` | array[string] | Matched evidence strings |
| `observed_patterns` | array[object] | Detailed pattern matches |
| `suggested_actions` | array[string] | Recommended response actions |

##### observed_patterns Object
```json
{
  "pattern_name": "SQL Injection",
  "description": "Detected 2 rule matches with score 10",
  "severity": "CRITICAL",
  "rule_matches": 2
}
```

#### Routing & Metadata
| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `route` | string | Processing path | "fast" (rule engine only), "slow" (with LLM) |
| `event_type` | string | Event classification | "fast_block", "fast_allow", "slow_block", "slow_explanation" |
| `source` | string | Decision source | "rule_engine", "llm_explainer" |

#### Explanation & Learning
| Field | Type | Description |
|-------|------|-------------|
| `explanation` | string | Human-readable analysis result |
| `learning_note` | string | Security education note |

#### Quality Control
| Field | Type | Description |
|-------|------|-------------|
| `hallucination_suspected` | boolean | LLM hallucination detection flag |
| `hallucination_reasons` | array[string] | Reasons if hallucination suspected |

#### Timestamps
| Field | Type | Description |
|-------|------|-------------|
| `generated_at` | string | ISO8601 timestamp for this result |

#### LLM-Specific (Optional)
| Field | Type | Description | Present When |
|-------|------|-------------|--------------|
| `llm_model` | string | LLM model identifier | route="slow" |
| `llm_reasoning` | string | LLM reasoning trace | route="slow" |

---

## Field Generation Logic

### Confidence Calculation
```python
# From LLM if available
if llm_output and llm_output.confidence:
    confidence = llm_output.confidence

# Otherwise from rule score
elif rule_score >= 10: confidence = 0.95
elif rule_score >= 5:  confidence = 0.85
elif rule_score >= 3:  confidence = 0.6
else:                  confidence = 0.4
```

### Attack Group Mapping
| Attack Type | Attack Group |
|-------------|--------------|
| SQL Injection | sql |
| Cross-Site Scripting | xss |
| Command Injection | command |
| Directory Traversal | path_traversal |
| Local File Inclusion | lfi |
| Server-Side Request Forgery | ssrf |
| Log Injection | log_injection |
| Unknown | generic |
| Normal | generic |

### Suggested Actions Logic
```python
if blocked:
    ["Block request", "Log attack for forensics", "Alert security team"]
elif fast_decision == "REVIEW":
    ["Review manually", "Log for monitoring", "Check user context"]
elif fast_decision == "MONITOR":
    ["Allow request", "Log for monitoring"]
else:  # ALLOW
    ["Allow request"]
```

### Event Type Logic
| Condition | Event Type |
|-----------|------------|
| blocked + route="fast" | fast_block |
| blocked + route="slow" | slow_block |
| !blocked + route="slow" | slow_explanation |
| !blocked + route="fast" | fast_allow |

---

## Example Outputs

### Example 1: Fast Path BLOCK (SQL Injection)
```json
{
  "result_json": {
    "results": [{
      "label": "SQL Injection",
      "attack_group": "sql",
      "attack_type": "sql_injection",
      "confidence": 0.95,
      "risk_score": 10,
      "severity": "CRITICAL",
      "evidence": ["SQL comment sequence detected", "SQL OR pattern found"],
      "observed_patterns": [{
        "pattern_name": "SQL Injection",
        "description": "Detected 2 rule matches with score 10",
        "severity": "CRITICAL",
        "rule_matches": 2
      }],
      "suggested_actions": ["Block request", "Log attack for forensics", "Alert security team"],
      "route": "fast",
      "event_type": "fast_block",
      "source": "rule_engine",
      "explanation": "SQL Injection attack detected - request blocked by rule engine",
      "learning_note": "SQL injection attacks can compromise database integrity. Always use parameterized queries and input validation.",
      "hallucination_suspected": false,
      "hallucination_reasons": [],
      "generated_at": "2026-02-09T16:18:32.491075+00:00"
    }],
    "flow_version": "capstone_http_analyzer.hybrid.v1",
    "generated_at": "2026-02-09T16:18:32.491088+00:00"
  }
}
```

### Example 2: Slow Path ALLOW (Normal Request)
```json
{
  "result_json": {
    "results": [{
      "label": "Normal",
      "attack_group": "generic",
      "attack_type": "none",
      "confidence": 0.9,
      "risk_score": 0,
      "severity": "Low",
      "evidence": [],
      "observed_patterns": [],
      "suggested_actions": ["Allow request"],
      "route": "slow",
      "event_type": "slow_explanation",
      "source": "llm_explainer",
      "explanation": "Request analyzed by LLM - appears legitimate",
      "learning_note": "Review request context and user behavior to assess risk.",
      "hallucination_suspected": false,
      "hallucination_reasons": [],
      "generated_at": "2026-02-09T16:18:32.492073+00:00",
      "llm_model": "groq/llama3-70b",
      "llm_reasoning": "No malicious patterns detected, legitimate search query"
    }],
    "flow_version": "capstone_http_analyzer.hybrid.v1",
    "generated_at": "2026-02-09T16:18:32.492084+00:00"
  }
}
```

### Example 3: Slow Path REVIEW (Unknown Pattern)
```json
{
  "result_json": {
    "results": [{
      "label": "Normal",
      "attack_group": "generic",
      "attack_type": "none",
      "confidence": 0.65,
      "risk_score": 3,
      "severity": "Medium",
      "evidence": ["Unusual Unicode sequence"],
      "observed_patterns": [{
        "pattern_name": "Unknown",
        "description": "Detected 1 rule matches with score 3",
        "severity": "Medium",
        "rule_matches": 1
      }],
      "suggested_actions": ["Review manually", "Log for monitoring", "Check user context"],
      "route": "slow",
      "event_type": "slow_explanation",
      "source": "llm_explainer",
      "explanation": "Unusual pattern requires manual review",
      "learning_note": "Unknown patterns require careful analysis to determine legitimacy and potential risk.",
      "hallucination_suspected": false,
      "hallucination_reasons": [],
      "generated_at": "2026-02-09T16:18:32.492540+00:00",
      "llm_model": "groq/llama3-70b",
      "llm_reasoning": "Zero-width characters detected - potential obfuscation technique"
    }],
    "flow_version": "capstone_http_analyzer.hybrid.v1",
    "generated_at": "2026-02-09T16:18:32.492547+00:00"
  }
}
```

---

## Implementation Notes

### File: response_builder.py
- **Purpose**: Transform internal state to external API format
- **Input**: SOCState with items array
- **Output**: Standardized result_json structure
- **Key Functions**:
  - `get_suggested_actions()`: Action recommendations
  - `get_learning_note()`: Security education content
  - `get_observed_patterns()`: Pattern extraction from evidence
  - `response_builder()`: Main transformation function

### Version History
- **v1.0**: Enhanced format with full field set (current)
  - Added: observed_patterns, suggested_actions, route, event_type
  - Added: source, explanation, learning_note
  - Added: confidence, risk_score, attack_group
  - Added: hallucination detection fields
  - Added: ISO8601 timestamps, flow_version

---

## Integration Guidelines

### API Consumers
1. **Parse result_json.results**: Array of analysis items
2. **Check route field**: "fast" = rule-based, "slow" = LLM-enhanced
3. **Use suggested_actions**: Automated response recommendations
4. **Display learning_note**: Security awareness content
5. **Monitor confidence**: Tune alerting thresholds

### Monitoring & Alerting
- **High confidence (>0.9) + BLOCK**: Instant alert
- **Medium confidence (0.6-0.9) + REVIEW**: Queue for analyst
- **Low confidence (<0.6)**: Log and monitor trends
- **Track route distribution**: fast vs slow path usage

### Logging & Audit
- **generated_at**: Timestamp for each result
- **flow_version**: Version tracking for audits
- **source**: Attribution to rule_engine or llm_explainer
- **evidence + observed_patterns**: Forensic trail
