import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/../'))
#!/usr/bin/env python3
"""
Demo: Fast Path (BLOCK) vs Slow Path (REVIEW → LLM)
Shows exact output structure at each stage
"""

from backends.rule_engine import analyze_request

def print_header(title):
    print(f"\n{'=' * 90}")
    print(f"  {title}")
    print(f"{'=' * 90}\n")

def demonstrate_paths():
    print_header("FAST PATH vs SLOW PATH - OUTPUT STRUCTURE DEMO")
    
    # ======================= FAST PATH (BLOCK) =======================
    print_header("FAST PATH: Score >= 5 → IMMEDIATE BLOCK")
    
    fast_payload = "id=1 UNION SELECT * FROM users"
    fast_result = analyze_request(fast_payload)
    
    print(f"Input:  '{fast_payload}'")
    print(f"\nRule Engine Output (analyze_request):")
    print(f"├─ attack_type:           '{fast_result['attack_type']}'")
    print(f"├─ inbound_anomaly_score: {fast_result['inbound_anomaly_score']}")
    print(f"├─ threshold:             {fast_result['threshold']}")
    print(f"├─ severity:              '{fast_result['severity']}'")
    print(f"├─ fast_decision:         '{fast_result['fast_decision']}'  ← BLOCK!")
    print(f"├─ evidence:              {fast_result['evidence']}")
    print(f"├─ matched_rules_count:   {fast_result['matched_rules_count']}")
    print(f"└─ attack_candidates:     {len(fast_result['attack_candidates'])} types detected")
    
    print(f"\n📍 Pipeline Flow:")
    print(f"   1. ✓ decode         → Extract: '{fast_payload}'")
    print(f"   2. ✓ rule_engine    → Score: {fast_result['inbound_anomaly_score']} → BLOCK")
    print(f"   3. ✓ router         → blocked=True, set final_msg")
    print(f"   4. ✗ cache          → Skip (already blocked)")
    print(f"   5. ✗ llm            → Skip (already blocked)")
    print(f"   6. ✓ response       → Return BLOCK verdict")
    
    print(f"\n📤 Final API Response:")
    print(f"{{")
    print(f"  'decision': 'BLOCK',")
    print(f"  'attack_type': '{fast_result['attack_type']}',")
    print(f"  'severity': '{fast_result['severity']}',")
    print(f"  'rule_score': {fast_result['inbound_anomaly_score']},")
    print(f"  'verdict': '[BLOCKED] {fast_result['attack_type']} | Score={fast_result['inbound_anomaly_score']} | Severity={fast_result['severity']}',")
    print(f"  'llm_model': None  ← NOT USED (fast path)")
    print(f"}}")
    
    
    # ======================= SLOW PATH (REVIEW) =======================
    print_header("SLOW PATH: Score 3-4 or Unknown → LLM ANALYSIS")
    
    slow_payload = "`whoami`"  # Score 4 - backtick execution
    slow_result = analyze_request(slow_payload)
    
    print(f"Input:  '{slow_payload}'")
    print(f"\nRule Engine Output (analyze_request):")
    print(f"├─ attack_type:           '{slow_result['attack_type']}'")
    print(f"├─ inbound_anomaly_score: {slow_result['inbound_anomaly_score']}")
    print(f"├─ threshold:             {slow_result['threshold']}")
    print(f"├─ severity:              '{slow_result['severity']}'")
    print(f"├─ fast_decision:         '{slow_result['fast_decision']}'  ← REVIEW!")
    print(f"├─ evidence:              {slow_result['evidence']}")
    print(f"├─ matched_rules_count:   {slow_result['matched_rules_count']}")
    print(f"└─ attack_candidates:     {len(slow_result['attack_candidates'])} types detected")
    
    print(f"\n📍 Pipeline Flow:")
    print(f"   1. ✓ decode         → Extract: '{slow_payload}'")
    print(f"   2. ✓ rule_engine    → Score: {slow_result['inbound_anomaly_score']} → REVIEW (needs verification)")
    print(f"   3. ✓ router         → blocked=False, no final_msg yet")
    print(f"   4. ✓ cache          → Check if seen before")
    print(f"   5. ✓ llm            → LLM analyzes context, intent, legitimacy")
    print(f"   6. ✓ response       → Return LLM verdict + rule score")
    
    print(f"\n🤖 LLM Analysis Input:")
    print(f"{{")
    print(f"  'query': '{slow_payload}',")
    print(f"  'rule_score': {slow_result['inbound_anomaly_score']},")
    print(f"  'attack_type': '{slow_result['attack_type']}',")
    print(f"  'severity': '{slow_result['severity']}',")
    print(f"  'evidence': {slow_result['evidence']},")
    print(f"  'rag_context': '... (relevant security docs) ...'")
    print(f"}}")
    
    print(f"\n📤 Final API Response:")
    print(f"{{")
    print(f"  'decision': 'ALLOW' or 'BLOCK',  ← LLM decides")
    print(f"  'attack_type': '{slow_result['attack_type']}',")
    print(f"  'severity': '{slow_result['severity']}',")
    print(f"  'rule_score': {slow_result['inbound_anomaly_score']},")
    print(f"  'verdict': 'LLM analysis: This appears to be... [BLOCK/ALLOW]',")
    print(f"  'llm_model': 'groq/llama3-70b'  ← LLM was used")
    print(f"}}")
    
    
    # ======================= UNKNOWN PATH =======================
    print_header("UNKNOWN PATH: Score 0 + No Pattern → LLM ANALYSIS")
    
    unknown_payload = "name='"
    unknown_result = analyze_request(unknown_payload)
    
    print(f"Input:  '{unknown_payload}'")
    print(f"\nRule Engine Output (analyze_request):")
    print(f"├─ attack_type:           '{unknown_result['attack_type']}'")
    print(f"├─ inbound_anomaly_score: {unknown_result['inbound_anomaly_score']}")
    print(f"├─ severity:              '{unknown_result['severity']}'")
    print(f"├─ fast_decision:         '{unknown_result['fast_decision']}'  ← REVIEW!")
    print(f"├─ requires_llm:          {unknown_result.get('requires_llm', False)}  ← Flag set")
    print(f"└─ evidence:              {unknown_result['evidence']}")
    
    print(f"\n📍 Pipeline Flow:")
    print(f"   1. ✓ decode         → Extract: '{unknown_payload}'")
    print(f"   2. ✓ rule_engine    → Score: 0, No patterns matched → REVIEW")
    print(f"   3. ✓ router         → blocked=False, escalate to LLM")
    print(f"   4. ✓ cache          → Check previous decisions")
    print(f"   5. ✓ llm            → LLM checks if legitimate or malicious")
    print(f"   6. ✓ response       → Return LLM verdict")
    
    print(f"\n🤖 Why LLM?")
    print(f"   - No known attack patterns matched")
    print(f"   - Could be legitimate: name='John' in SQL query")
    print(f"   - Could be malicious: SQLi attempt with single quote")
    print(f"   - Context matters → LLM analyzes semantics")
    
    print(f"\n📤 Final API Response:")
    print(f"{{")
    print(f"  'decision': 'ALLOW',  ← LLM: 'Appears to be normal form input'")
    print(f"  'attack_type': 'Unknown',")
    print(f"  'severity': 'Info',")
    print(f"  'rule_score': 0,")
    print(f"  'verdict': 'LLM: No malicious intent detected. Likely legitimate...',")
    print(f"  'llm_model': 'groq/llama3-70b'")
    print(f"}}")
    
    
    # ======================= COMPARISON TABLE =======================
    print_header("COMPARISON: FAST vs SLOW PATH")
    
    print(f"{'Aspect':<25} | {'FAST PATH (BLOCK)':<35} | {'SLOW PATH (REVIEW/MONITOR)':<35}")
    print("-" * 100)
    print(f"{'Trigger':<25} | {'Score >= 5':<35} | {'Score 3-4 OR Score 0 (unknown)':<35}")
    print(f"{'Decision Speed':<25} | {'Immediate (~5ms)':<35} | {'Slower (~500ms+ with LLM)':<35}")
    print(f"{'Rule Engine Only?':<25} | {'Yes - sufficient evidence':<35} | {'No - needs verification':<35}")
    print(f"{'LLM Called?':<25} | {'No (skip)':<35} | {'Yes (required)':<35}")
    print(f"{'Cache Checked?':<25} | {'No (already blocked)':<35} | {'Yes (might have verdict)':<35}")
    print(f"{'RAG Used?':<25} | {'No':<35} | {'Yes (context for LLM)':<35}")
    print(f"{'Final Verdict From':<25} | {'rule_engine.py':<35} | {'llm_backend.py':<35}")
    print(f"{'Response llm_model':<25} | {'None':<35} | {'groq/llama3-70b':<35}")
    print(f"{'Use Case':<25} | {'Clear attacks (SQLi, XSS)':<35} | {'Borderline, unknown, context':<35}")
    
    
    # ======================= DECISION MATRIX =======================
    print_header("DECISION MATRIX")
    
    test_cases = [
        ("hello world", "ALLOW (whitelist)", "FAST", "Safe pattern"),
        ("id=1 UNION SELECT", "BLOCK", "FAST", "Score: 10"),
        ("`whoami`", "REVIEW → LLM", "SLOW", "Score: 4"),
        ("name='", "REVIEW → LLM", "SLOW", "Unknown pattern"),
        ("../etc/passwd", "MONITOR → LLM", "SLOW", "Score: 2"),
        ("<script>alert(1)</script>", "BLOCK", "FAST", "Score: 9"),
    ]
    
    print(f"{'Input':<30} | {'Rule Decision':<20} | {'Path':<8} | {'Reason':<15}")
    print("-" * 90)
    for inp, decision, path, reason in test_cases:
        print(f"{inp:<30} | {decision:<20} | {path:<8} | {reason:<15}")

if __name__ == "__main__":
    demonstrate_paths()
    
    print("\n" + "=" * 90)
    print("KEY TAKEAWAYS")
    print("=" * 90)
    print("""
1. FAST PATH (rule_engine only):
   - For obvious threats (score >= 5)
   - Returns: BLOCK decision immediately
   - No LLM overhead (~5ms response time)
   - Output: {'decision': 'BLOCK', 'attack_type': '...', 'llm_model': None}

2. SLOW PATH (rule_engine → LLM):
   - For borderline cases (score 3-4) or unknown (score 0)
   - Returns: REVIEW → LLM analyzes → ALLOW/BLOCK
   - Uses LLM + RAG context (~500ms response time)
   - Output: {'decision': 'ALLOW/BLOCK', 'llm_model': 'groq/llama3-70b', ...}

3. WHY HYBRID?
   - Fast path: 80% of requests (clear attacks or safe)
   - Slow path: 20% of requests (needs context)
   - Best of both: Speed + Intelligence
""")
