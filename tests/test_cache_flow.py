"""Test cache hit/miss flow"""

import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from graph_app import soc_app
from backends.cache_backend import cache_info

# Seed some test data
print("=== SEEDING TEST DATA ===")
try:
    from backends.rag_backend import add_rag_example
    add_rag_example("id=1 UNION SELECT password FROM users", is_anomalous=True, attack_type="SQL Injection")
    add_rag_example("<script>alert(1)</script>", is_anomalous=True, attack_type="XSS")
    add_rag_example("../../etc/passwd", is_anomalous=True, attack_type="Path Traversal")
    add_rag_example("/api/users", is_anomalous=False)
    print("✅ RAG data seeded\n")
except Exception as e:
    print(f"⚠️ RAG seed error: {e}\n")

print(f"Initial cache: {cache_info()}\n")

# Test 1: Cache MISS (first request, slow path)
print("=== TEST 1: CACHE MISS (SLOW PATH) ===")
test_request_1 = "/api/products?category=electronics"

result_1 = soc_app.invoke({
    "requests": [test_request_1]
})

print(json.dumps(result_1.get("result_json"), indent=2, ensure_ascii=False))
print(f"\nCache after test 1: {cache_info()}\n")

# Test 2: Cache HIT (same request)
print("=== TEST 2: CACHE HIT (SAME REQUEST) ===")

result_2 = soc_app.invoke({
    "requests": [test_request_1]
})

print(json.dumps(result_2.get("result_json"), indent=2, ensure_ascii=False))
print(f"\nCache after test 2: {cache_info()}\n")

# Test 3: FAST PATH (rule engine blocks)
print("=== TEST 3: FAST PATH (RULE ENGINE BLOCK) ===")
test_request_3 = "/admin?id=1 OR 1=1"

result_3 = soc_app.invoke({
    "requests": [test_request_3]
})

print(json.dumps(result_3.get("result_json"), indent=2, ensure_ascii=False))
print(f"\nCache after test 3: {cache_info()}\n")

# Test 4: Same attack again (should use cache)
print("=== TEST 4: SAME ATTACK (CACHED BLOCK) ===")

result_4 = soc_app.invoke({
    "requests": [test_request_3]
})

print(json.dumps(result_4.get("result_json"), indent=2, ensure_ascii=False))
print(f"\nFinal cache: {cache_info()}")
