#!/usr/bin/env python3
"""Test hallucination detection improvements."""

import sys
import json
import os

# Add path to imports
sys.path.insert(0, os.getcwd())

from soc_state import SOCState
from nodes.nodes_llm import _detect_hallucination, _apply_llm_result
from nodes.nodes_router import router_node


def test_hallucination_detection():
    """Test that hallucination detection works correctly."""
    print("=" * 60)
    print("TEST 1: Hallucination Detection")
    print("=" * 60)
    
    # Case 1: LLM hallucinating Base64 payload not in request
    item = {
        "id": "test1", 
        "raw_request": "aaaa",
        "rule_score": 0,
        "attack_type": "XSS",
        "severity": "Info",
        "blocked": False,
        "final_msg": "",
        "hallucination_suspected": False,
    }
    
    analysis_data = {
        "threat_score": 8,
        "attack_type": "XSS",
        "justification": "The request contains a Base64 encoded payload that decodes to malicious JavaScript code",
        "action": "BLOCK",
        "recommendation": "Further investigation required"
    }
    
    hallucinated = _detect_hallucination(item, analysis_data)
    print(f"\n✓ Input: 'aaaa'")
    print(f"  Rule Score: 0")
    print(f"  LLM threat_score: 8")
    print(f"  LLM talks about: Base64 encoding")
    print(f"  Hallucination detected: {hallucinated}")
    assert hallucinated == True, "Should detect hallucination when threat_score >= 6 and rule_score == 0"
    print("  ✅ PASS: Correctly detected hallucination")
    
    # Case 2: Legitimate short request without hallucination
    item2 = {
        "id": "test2",
        "raw_request": "test",
        "rule_score": 0,
        "attack_type": "Normal",
        "severity": "Info",
        "blocked": False,
        "final_msg": "",
        "hallucination_suspected": False,
    }
    
    analysis_data2 = {
        "threat_score": 0,
        "attack_type": "Benign",
        "justification": "Generic text, no malicious content",
        "action": "ALLOW",
        "recommendation": "Allow request"
    }
    
    hallucinated2 = _detect_hallucination(item2, analysis_data2)
    print(f"\n✓ Input: 'test'")
    print(f"  Rule Score: 0")
    print(f"  LLM threat_score: 0")
    print(f"  Hallucination detected: {hallucinated2}")
    assert hallucinated2 == False, "Should not detect hallucination for benign content"
    print("  ✅ PASS: Correctly identified benign content")


def test_router_logic():
    """Test improved router logic."""
    print("\n" + "=" * 60)
    print("TEST 2: Router Node Logic - rule_score=0 Fast Path")
    print("=" * 60)
    
    state = {
        "requests": ["aaaa"],
        "items": [{
            "id": "item1",
            "raw_request": "aaaa",
            "rule_score": 0,
            "severity": "Info",
            "attack_type": "Unknown",
            "fast_decision": "",
            "evidence": ["no_pattern_match"],
            "blocked": False,
            "final_msg": ""
        }],
        "results": []
    }
    
    updated_state = router_node(state)
    item = updated_state["items"][0]
    
    print(f"\n✓ Input: rule_score=0, evidence=['no_pattern_match']")
    print(f"  Fast Decision: {item.get('fast_decision')}")
    print(f"  Blocked: {item.get('blocked')}")
    print(f"  Final Message: {item.get('final_msg')}")
    
    assert item["fast_decision"] == "ALLOW", "rule_score=0 should result in ALLOW"
    assert item["blocked"] == False, "rule_score=0 should not block"
    assert "[FAST_ALLOW]" in item["final_msg"], "Should indicate fast allow"
    print("  ✅ PASS: Correctly fast-allowed rule_score=0 requests")


def test_apply_llm_result():
    """Test LLM result application with hallucination handling."""
    print("\n" + "=" * 60)
    print("TEST 3: Apply LLM Result - Hallucination Handling")
    print("=" * 60)
    
    # Item with hallucination
    item = {
        "id": "test",
        "raw_request": "aaaa",
        "rule_score": 0,
        "attack_type": "XSS",
        "severity": "Info",
        "blocked": False,
        "final_msg": "",
        "hallucination_suspected": False,
    }
    
    result = {
        "analysis": {
            "threat_score": 8,
            "attack_type": "XSS",
            "justification": "Base64 payload found",
            "action": "BLOCK",
            "recommendation": "Further investigation"
        },
        "model": "openai/gpt-oss-120b",
        "raw_text": '{"threat_score": 8, "attack_type": "XSS", ...}'
    }
    
    _apply_llm_result(item, result)
    
    print(f"\n✓ LLM returned threat_score=8, action=BLOCK for input 'aaaa'")
    print(f"  Hallucination Suspected: {item['hallucination_suspected']}")
    print(f"  Final Decision (blocked): {item['blocked']}")
    print(f"  Fast Decision: {item['fast_decision']}")
    
    assert item["hallucination_suspected"] == True, "Should flag hallucination"
    assert item["blocked"] == False, "Hallucinated findings should not block"
    assert item["fast_decision"] == "ALLOW", "Should demote to ALLOW"
    print("  ✅ PASS: Correctly handled hallucinated LLM output")


def test_confidence_validation():
    """Test that low threat scores don't trigger blocks."""
    print("\n" + "=" * 60)
    print("TEST 4: Confidence Validation - Low Score BLOCK Action")
    print("=" * 60)
    
    item = {
        "id": "test",
        "raw_request": "SELECT * FROM users",
        "rule_score": 2,
        "attack_type": "SQL Injection",
        "severity": "Low",
        "blocked": False,
        "final_msg": "",
        "hallucination_suspected": False,
    }
    
    result = {
        "analysis": {
            "threat_score": 3,  # Low score despite BLOCK action
            "attack_type": "SQL Injection",
            "justification": "Possible SQL injection",
            "action": "BLOCK",
            "recommendation": "Review"
        },
        "model": "openai/gpt-oss-120b",
        "raw_text": '...'
    }
    
    _apply_llm_result(item, result)
    
    print(f"\n✓ LLM returned threat_score=3 with action=BLOCK")
    print(f"  Blocked: {item['blocked']}")
    print(f"  Fast Decision: {item['fast_decision']}")
    print(f"  Final Message: {item['final_msg']}")
    
    assert item["blocked"] == False, "threat_score < 6 should not block even if action=BLOCK"
    assert item["fast_decision"] == "REVIEW", "Should demote to REVIEW"
    print("  ✅ PASS: Correctly rejected low-confidence BLOCK action")


if __name__ == "__main__":
    try:
        test_hallucination_detection()
        test_router_logic()
        test_apply_llm_result()
        test_confidence_validation()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print("\nSummary of Improvements:")
        print("1. ✅ Hallucination detection enabled")
        print("2. ✅ rule_score=0 fast-allows (no LLM)")
        print("3. ✅ LLM Base64/encoding hallucination detection")
        print("4. ✅ Confidence validation (threat_score >= 6 required for BLOCK)")
        print("5. ✅ System prompt clarifies RAG examples vs actual request")
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
