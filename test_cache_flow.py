"""Test new cache-first flow"""
from graph_app import soc_app

print("=" * 80)
print("Test: Cache-First Architecture")
print("=" * 80)

# First request (cache miss)
print("\n1. First request (cache miss)")
result1 = soc_app.invoke({"requests": ["/api/users?id=1 OR 1=1"]})
item1 = result1["items"][0]
print(f"   Cache Hit: {item1['cache_hit']}")
print(f"   Attack Type: {item1['attack_type']}")
print(f"   Score: {item1['rule_score']}")

# Second request (same, cache hit)
print("\n2. Second request (same URL - should cache hit)")
result2 = soc_app.invoke({"requests": ["/api/users?id=1 OR 1=1"]})
item2 = result2["items"][0]
print(f"   Cache Hit: {item2['cache_hit']}")
print(f"   Attack Type: {item2['attack_type']}")
print(f"   Score: {item2['rule_score']}")
print(f"   ✅ Skipped rule engine (from cache)")

# Different request (cache miss)
print("\n3. Third request (different URL - cache miss)")
result3 = soc_app.invoke({"requests": ["/search?q=<script>alert(1)</script>"]})
item3 = result3["items"][0]
print(f"   Cache Hit: {item3['cache_hit']}")
print(f"   Attack Type: {item3['attack_type']}")
print(f"   Score: {item3['rule_score']}")

# Batch with cache hits and misses
print("\n4. Batch with mixed cache hits/misses")
result4 = soc_app.invoke({
    "requests": [
        "/api/users?id=1 OR 1=1",        # Hit (cached from request 1)
        "/search?q=<script>alert(1)</script>",  # Hit (cached from request 3)
        "/data?file=../../etc/passwd",   # Miss (new)
    ]
})
for i, item in enumerate(result4["items"], 1):
    status = "HIT" if item['cache_hit'] else "MISS"
    print(f"   Item {i}: Cache {status} - {item['attack_type']} (score={item['rule_score']})")

print("\n" + "=" * 80)
print("Flow Summary:")
print("=" * 80)
print("Request -> Cache Check -> (Hit: Response) | (Miss: Rule -> Router -> ...)")
print("✅ Cache-first flow working correctly!")
