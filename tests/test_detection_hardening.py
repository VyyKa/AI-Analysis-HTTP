"""Regression tests for stricter attack classification and auto-block behavior."""

import sys
from pathlib import Path

# Ensure local imports work when tests are run from repository root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rule_engine import analyze_request, is_normal_request
from nodes.nodes_llm import _apply_llm_result


def test_encoded_ssi_exec_not_fast_allowed() -> None:
    raw_request = (
        "GET /?q=%26lt%3B%21--%23exec%2520cmd%3D%26quot%3B%2Fusr%2Fbin%2Fid%3B--%26gt%3B&sort=new&limit=12 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "User-Agent: pytest\r\n"
    )

    assert is_normal_request(raw_request) is False

    result = analyze_request(raw_request)
    assert result["fast_decision"] == "BLOCK"
    assert result["rule_score"] >= 5
    assert result["attack_type"] == "Command Injection"


def test_usr_bin_id_payload_auto_blocked() -> None:
    raw_request = (
        "GET /?q=a%29%3B%2Fusr%2Fbin%2Fid%3B&sort=new&limit=12 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "User-Agent: pytest\r\n"
    )

    result = analyze_request(raw_request)

    assert result["fast_decision"] == "BLOCK"
    assert result["rule_score"] >= 5
    assert result["attack_type"] == "Command Injection"


def test_pipe_id_payload_auto_blocked() -> None:
    raw_request = (
        "GET /?q=%2Findex.html%7Cid%7C&sort=new&limit=12 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "User-Agent: pytest\r\n"
    )

    result = analyze_request(raw_request)

    assert result["fast_decision"] == "BLOCK"
    assert result["rule_score"] >= 5
    assert result["attack_type"] == "Command Injection"


def test_llm_cannot_downgrade_rule_attack_type() -> None:
    item = {
        "id": "test-item",
        "raw_request": "GET /?q=%2Findex.html%7Cid%7C HTTP/1.1",
        "rule_score": 5,
        "attack_type": "Command Injection",
        "severity": "High",
        "blocked": False,
        "fast_decision": "REVIEW",
        "final_msg": "",
        "hallucination_suspected": False,
    }

    llm_result = {
        "analysis": {
            "threat_score": 1,
            "attack_type": "Benign",
            "justification": "No concrete exploit chain found.",
            "action": "ALLOW",
            "recommendation": "Allow request",
        },
        "model": "mock",
        "raw_text": "",
    }

    _apply_llm_result(item, llm_result)

    assert item["attack_type"] == "Command Injection"
    assert item["blocked"] is False
    assert item["fast_decision"] == "REVIEW"
