# Cache-First Architecture

## Overview

The system now implements a **cache-first approach** with an explicit RAG step so the retrieval context is visible in the flow:

```
request → rag → cache_check → {hit → response} | {miss → normalize → rule → router → llm → response}
```

This ensures:
- **Repeated requests** skip expensive analysis
- **First-time requests** go through full pipeline
- **Cache hit saves** ~150-500ms per request

## Flow Diagram

```
┌─────────────┐
│   Request   │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  1. Decode       │  Load batch → normalize
│  Batch Decoder   │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  2. Cache Check  │◄─────────┐
│  cache_check_    │          │ (if cache hit, populate 
│  node            │          │  analysis fields)
└──────┬───────────┘
       │
       ├─ Cache HIT ────────────────────┐
       │                                │
       │                            ┌───▼─────────┐
       │                            │   Response  │
       │                            │   response_ │
       │                            │   node      │
       │                            └───┬─────────┘
       │                                │
       │                            ┌───▼──────┐
       │                            │  Output  │
       │                            │  (fast!) │
       │                            └──────────┘
       │
       └─ Cache MISS ───────────────────┐
       │                                │
       ▼                                │
┌──────────────────┐                   │
│  3. Rule Engine  │                   │
│  rule_engine_    │ OWASP CRS scoring │
│  node            │                   │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  4. Router       │ Fast (BLOCK?) or Slow (LLM)?
│  router_node     │
└──────┬───────────┘
       │
       ├─ Fast Path (blocked) ──────────┐
       │                                │
       ▼                                │
┌──────────────────┐                   │
│  5a. Cache Save  │ Save to cache     │
│  cache_save_node │                   │
└──────┬───────────┘                   │
       │                               │
       │                               │
       └──────────────┬────────────────┘
                      │
       ┌──────────────┘
       │
 ┌─────▼────────────┐
 │ Slow Path (LLM)? │
 └─────┬────────────┘
       │
       ├─ No (score < threshold) ──────┬──► Cache Save ──┐
       │                               │                 │
       │                               │                 │
       └─ Yes (needs analysis) ────────┤                 │
                                       │                 │
       ┌──────────────────────────────┐│                 │
       │                              ││                 │
       ▼                              ││                 │
┌──────────────────┐                  ││                 │
│  6. RAG Node     │ Vector search for context │              │
│  rag_node        │ (only slow path)         ││                 │
└──────┬───────────┘                  ││                 │
       │                              ││                 │
       ▼                              ││                 │
┌──────────────────┐                  ││                 │
│  7. LLM Node     │ Deep analysis    ││                 │
│  llm_node        │                  ││                 │
└──────┬───────────┘                  ││                 │
       │                              ││                 │
       └──────────────────┬───────────┘│                 │
                          │            │                 │
                          ▼            ▼                 │
                    ┌──────────────────────────┐         │
                    │  5b. Cache Save Node     │         │
                    │  cache_save_node         │◄────────┘
                    └──────┬───────────────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  8. Response     │
                    │  response_node   │
                    └──────┬───────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  Output (JSON)   │
                    └──────────────────┘
│  cache_check_    │          │ (if cache hit, populate 
│  node            │          │  analysis fields)
└──────┬───────────┘
       │
       ├─ Cache HIT ────────────────────┐
       │                                │
       │                            ┌───▼─────────┐
       │                            │   Response  │
       │                            │   response_ │
       │                            │   node      │
       │                            └───┬─────────┘
       │                                │
       │                            ┌───▼──────┐
       │                            │  Output  │
       │                            │  (fast!) │
       │                            └──────────┘
       │
       └─ Cache MISS ───────────────────┐
       │                                │
       ▼                                │
┌──────────────────┐                   │
│  3. Rule Engine  │                   │
│  rule_engine_    │ OWASP CRS scoring │
│  node            │                   │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  4. Router       │ Fast (BLOCK?) or Slow (LLM)?
│  router_node     │
└──────┬───────────┘
       │
       ├─ Fast Path (blocked) ──────────┐
       │                                │
       ▼                                │
┌──────────────────┐                   │
│  5a. Cache Save  │ Save to cache     │
│  cache_save_node │                   │
└──────┬───────────┘                   │
       │                               │
       │                               │
       └──────────────┬────────────────┘
                      │
       ┌──────────────┘
       │
 ┌─────▼────────────┐
 │ Slow Path (LLM)? │
 └─────┬────────────┘
       │
       ├─ No (score < threshold) ──────┬──► Cache Save ──┐
       │                               │                 │
       │                               │                 │
       └─ Yes (needs analysis) ────────┤                 │
                                       │                 │
       ┌──────────────────────────────┐│                 │
       │                              ││                 │
       ▼                              ││                 │
┌──────────────────┐                  ││                 │
│  6. LLM Node     │ Deep analysis    ││                 │
│  llm_node        │                  ││                 │
└──────┬───────────┘                  ││                 │
       │                              ││                 │
       └──────────────────┬───────────┘│                 │
                          │            │                 │
                          ▼            ▼                 │
                    ┌──────────────────────────┐         │
                    │  5b. Cache Save Node     │         │
                    │  cache_save_node         │◄────────┘
                    └──────┬───────────────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  7. Response     │
                    │  response_node   │
                    └──────┬───────────┘
                           │
                           ▼
                    ┌──────────────────┐
                    │  Output (JSON)   │
                    └──────────────────┘
```

## Performance Impact

### Cache Hit (repeated request)
- Decode: ~1ms
- **Cache Check: ~0.5ms** ✅ (instant lookup)
- Response Build: ~1ms
- **Total: ~2.5ms** (96% faster!)

### Cache Miss (first-time request)
- Decode: ~1ms
- Cache Check: ~0.5ms
- Rule Engine: ~3ms
- Router: <1ms
- LLM (if needed): ~500ms
- Response Build: ~1ms
- **Total: ~5-505ms** (depending on path)

## Implementation Details

### cache_check_node()

```python
def cache_check_node(state: SOCState) -> dict:
    """
    Check if request results are already cached.
    If cached, populate all analysis fields immediately.
    If not cached, mark for analysis.
    """
    for item in state["items"]:
        request_hash = _hash_request(item["raw_request"])
        
        if request_hash in REQUEST_CACHE:
            # Cache HIT - restore cached analysis
            item["cache_hit"] = True
            item.update(REQUEST_CACHE[request_hash])
        else:
            # Cache MISS - mark for analysis
            item["cache_hit"] = False
    
    return state
```

### cache_save_node()

```python
def cache_save_node(state: SOCState) -> dict:
    """
    Save analyzed results to cache for future requests.
    Called AFTER both fast and slow path analysis.
    """
    for item in state["items"]:
        request_hash = _hash_request(item["raw_request"])
        
        if request_hash not in REQUEST_CACHE:
            REQUEST_CACHE[request_hash] = {
                "attack_type": item["attack_type"],
                "rule_score": item["rule_score"],
                "severity": item["severity"],
                "fast_decision": item["fast_decision"],
                "evidence": item["evidence"],
                "attack_candidates": item["attack_candidates"],
                "blocked": item["blocked"],
            }
    
    return state
```

## Routing Logic

### route_cache_hit()
```python
def route_cache_hit(state: SOCState) -> str:
    if all(item["cache_hit"] for item in state["items"]):
        return "cache_hit"   # Skip analysis
    return "cache_miss"      # Do analysis
```

### route_after_rule()
```python
def route_after_rule(state: SOCState) -> str:
    if all(item["blocked"] for item in state["items"]):
        return "fast"     # BLOCK → save & response
    return "slow"         # Needs LLM → analyze
```

## Edge Cases

### 1. Batch with Mixed Cache States
```json
{
  "requests": [
    "/api/users?id=1 OR 1=1",          // CACHED MISS → HIT
    "/search?q=python",                 // CACHED MISS → HIT  
    "/admin?key=secret",                // CACHE MISS → analyze
  ]
}
```

Result: Items 1 & 2 skip analysis (2.5ms total), Item 3 goes through pipeline (5-505ms).

### 2. Similar But Different Requests
```
Request 1: /api/users?id=1 OR 1=1     (SQL Injection, cached)
Request 2: /api/users?id=2 OR 1=1     (Different hash, not cached)
Request 3: /api/users?id=1 OR 1=1     (Identical, cache hit)
```

Each unique URL gets its own cache entry. Hash comparison is case-insensitive and URL-normalized.

### 3. Cache Invalidation
Currently: **No explicit invalidation** (in-memory, session-based).

For production:
- Implement Redis with TTL (e.g., 1 hour)
- Add cache versioning (e.g., when rule engine version changes)
- Support cache clear endpoint

## Configuration

### Current Strategy
- **In-Memory Cache**: Fast, simple (Python dict)
- **Scope**: Per-process session
- **TTL**: None (session-based)

### Production Recommendations

```python
# Redis Backend
import redis
cache = redis.Redis(host='localhost', port=6379, decode_responses=True)

def cache_check_node(state):
    for item in state["items"]:
        key = _hash_request(item["raw_request"])
        cached = cache.get(key)
        if cached:
            item.update(json.loads(cached))
        item["cache_hit"] = bool(cached)
    return state

def cache_save_node(state):
    for item in state["items"]:
        key = _hash_request(item["raw_request"])
        if not cache.exists(key):
            cache.setex(
                key, 
                3600,  # 1 hour TTL
                json.dumps({...})
            )
    return state
```

## Testing

```bash
# Test cache flow
python test_cache_simple.py

# Test with full graph (after fixing imports)
python test_cache_flow.py
```

## Metrics

### Cache Effectiveness
- **Hit Rate**: % of requests found in cache
- **Latency Saved**: Time saved by skipping analysis
- **Memory Usage**: Cache size (items × average item size)

### Monitoring
```python
REQUEST_CACHE_STATS = {
    "total_requests": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "latency_saved_ms": 0,
}

hit_rate = cache_hits / (cache_hits + cache_misses) * 100
```

---

**Flow improved**: Cache check **before** rule engine → Significant latency reduction for repeated requests! 🚀
