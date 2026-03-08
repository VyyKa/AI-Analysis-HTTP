"""Regression tests for stricter attack classification and auto-block behavior."""

import sys
from pathlib import Path

# Ensure local imports work when tests are run from repository root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rule_engine import analyze_request, is_normal_request
from nodes.nodes_llm import _apply_llm_result, _detect_hallucination


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


def test_sqlmap_waitfor_delay_not_fast_allowed() -> None:
    raw_request = (
        "GET /?q=hi%20WAITFOR%20DELAY%20%270%3A0%3A5%27--%20rSkY HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "Accept: */*\r\n"
        "User-Agent: sqlmap/1.10.2.18#dev (https://sqlmap.org)\r\n"
    )

    result = analyze_request(raw_request)
    assert result["fast_decision"] != "ALLOW"
    assert result["attack_type"] == "SQL Injection"
    assert result["rule_score"] >= 5


def test_sqlmap_extractvalue_payload_not_fast_allowed() -> None:
    raw_request = (
        "GET /?q=hi%20AND%20EXTRACTVALUE%282447%2CCONCAT%280x5c%2C0x717a7a6b71%2C"
        "%28SELECT%20%28ELT%282447%3D2447%2C1%29%29%29%2C0x71716b7871%29%29 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "Accept: */*\r\n"
        "User-Agent: sqlmap/1.10.2.18#dev (https://sqlmap.org)\r\n"
    )

    result = analyze_request(raw_request)
    assert result["fast_decision"] != "ALLOW"
    assert result["attack_type"] == "SQL Injection"
    assert result["rule_score"] >= 5


def test_sqlmap_dbms_pipe_payload_not_fast_allowed() -> None:
    raw_request = (
        "GET /?q=hi%29%20AND%206345%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%28117%29%7C%7C"
        "CHR%2881%29%7C%7CCHR%2868%29%7C%7CCHR%2899%29%2C5%29%20AND%20%285246%3D5246 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "Accept: */*\r\n"
        "User-Agent: sqlmap/1.10.2.18#dev (https://sqlmap.org)\r\n"
    )

    result = analyze_request(raw_request)
    assert result["fast_decision"] != "ALLOW"
    assert result["attack_type"] == "SQL Injection"
    assert result["rule_score"] >= 5


def test_encoded_xss_not_marked_as_hallucination() -> None:
    raw_request = (
        "GET /?q=%3Ca%3Ascript+xmlns%3Aa%3D%22http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml%22%3E"
        "alert%281%29%3C%2Fa%3Ascript%3E&sort=new&limit=12 HTTP/1.1\r\n"
        "Host: http-ingest:9002\r\n"
        "User-Agent: pytest\r\n"
    )

    item = {
        "id": "xss-encoded-case",
        "raw_request": raw_request,
        "rule_score": 0,
        "attack_type": "Unknown",
        "severity": "Info",
        "blocked": False,
        "fast_decision": "REVIEW",
        "final_msg": "",
        "hallucination_suspected": False,
    }

    analysis_data = {
        "threat_score": 8,
        "attack_type": "XSS",
        "justification": (
            "The request contains a URL-encoded XSS payload that decodes to "
            "<a:script xmlns:a=\"http://www.w3.org/1999/xhtml\">alert(1)</a:script>."
        ),
        "action": "BLOCK",
        "recommendation": "Block request",
    }

    assert _detect_hallucination(item, analysis_data) is False

    result = {
        "analysis": analysis_data,
        "model": "mock-model",
        "raw_text": "{}",
    }
    _apply_llm_result(item, result)

    assert item["hallucination_suspected"] is False
    assert item["blocked"] is True
    assert item["fast_decision"] == "BLOCK"
