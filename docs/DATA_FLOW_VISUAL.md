## Complete LangGraph SOC Analyzer - Data Flow & RAG Source

```mermaid
graph TD
    subgraph DATASET["📊 RAG DATASET SOURCES"]
        S1["Option 1: seed_rag.py<br/>(6 manual examples)"]
        S2["Option 2: seed_rag_from_csic.py<br/>(61,792 real HTTP payloads<br/>from Hugging Face)"]
        both["Both → ChromaDB 'soc_attacks'<br/>(In-memory collection)"]
        S1 --> both
        S2 --> both
    end

    subgraph INPUT["📥 USER INPUT"]
        USER["User submits:<br/>requests: ['GET /api', ...]"]
    end

    subgraph NODES["🔄 GRAPH NODES & FLOW"]
        N1["1️⃣ DECODE<br/>batch_decoder()"]
        N2["2️⃣ RULE ENGINE<br/>rule_engine_node()"]
        N3["3️⃣ ROUTER<br/>router_node()"]
        N4["4️⃣ CACHE CHECK<br/>cache_router_node()"]
        N5["5️⃣ LLM ANALYZER<br/>llm_node()"]
        N6["6️⃣ CACHE SAVE<br/>cache_save_node()"]
        N7["7️⃣ RESPONSE<br/>response_node()"]
        
        N1 -->|Parse input| N2
        N2 -->|Score, severity,<br/>attack_type| N3
        N3 -->|Rule decision| DECISION{Fast or Slow?}
        DECISION -->|All blocked| FASTSAVE["→ cache_save"]
        DECISION -->|Some not blocked| N4
        FASTSAVE --> N6
        N4 -->|Cache HIT| CACHE_HIT["→ Skip LLM"]
        N4 -->|Cache MISS| RAG["🎯 RAG VECTOR SEARCH<br/>SentenceTransformer encoding<br/>ChromaDB top-3 similarity<br/>Format context"]
        CACHE_HIT --> N6
        RAG --> N5
        N5 -->|Groq LLM +<br/>RAG context| N6
        N6 --> N7
        N7 -->|Rich JSON output| END["✅ Response"]
    end

    subgraph BACKENDS["🔧 BACKEND SERVICES"]
        RAG_DB["rag_backend.py<br/>- ChromaDB collection<br/>- vector_search()<br/>- rag_list_parser()"]
        CACHE_DB["cache_backend.py<br/>- SHA256 hash cache<br/>- cache_get/set()"]
        RULES["rule_engine.py<br/>- 15 attack types<br/>- 80+ patterns<br/>- Anomaly scoring"]
        LLM["llm_backend.py<br/>- Groq API client<br/>- llama-3.3-70b<br/>- System prompt"]
    end

    both -.->|Seed into| RAG_DB
    N4 -.->|Queries| RAG_DB
    N2 -.->|Uses| RULES
    N4 -.->|Uses| CACHE_DB
    N5 -.->|Sends request<br/>+ RAG context| LLM
    N6 -.->|Saves result| CACHE_DB

    DATASET --> INPUT
    INPUT --> NODES
    NODES --> BACKENDS
    NODES --> END

    style DATASET fill:#e1f5ff
    style INPUT fill:#fff3e0
    style NODES fill:#f3e5f5
    style BACKENDS fill:#e8f5e9
    style RAG_DB fill:#c8e6c9
    style CACHE_DB fill:#c8e6c9
    style RULES fill:#c8e6c9
    style LLM fill:#c8e6c9
    style END fill:#a5d6a7
```

### RAG Dataset Flow Explained

**ChromaDB Storage Structure:**
```
Item {
  ID: SHA256(request_text)           ← Unique fingerprint
  Content: Request text             ← The HTTP payload
  Metadata: {
    "label": "normal" | "anomalous"
    "attack_type": "SQL Injection" | "XSS" | ... | "normal"
  }
  Embedding: [384D vector]          ← SentenceTransformer encoding
}
```

**Vector Search Process (when cache miss):**
1. User request → SentenceTransformer encoding (384D vector)
2. ChromaDB similarity search → top-3 closest stored items
3. Format as RAG context string: `[ANOMALOUS] SQL Injection: id=1 UNION SELECT...`
4. Pass to Groq LLM along with the new request
5. LLM can now say: *"This request pattern matches known SQL injections from training data"*

### Two Dataset Options

| Feature | seed_rag.py | seed_rag_from_csic.py |
|---------|-------------|----------------------|
| **Items** | 6 hard-coded | 61,792 HTTP payloads |
| **Download** | Instant | ~2-5 min first time |
| **Source** | Hard-coded | Hugging Face |
| **Use Case** | Quick testing | Production quality |
| **RAG Quality** | Basic examples | Real attack patterns |
| **Command** | `python scripts/seed_rag.py` | `python scripts/seed_rag_from_csic.py` |

### Complete Request Lifecycle

```
User {requests: ["id=1 UNION SELECT ..."]}
  ↓
[decode] Parse batch → items[]
  ↓
[rule] OWASP CRS check → rule_score=8, attack_type=SQL Injection
  ↓
[router] Decide: blocked? YES → fast path
  ↓
[cache_save] Save to cache (SHA256 key)
  ↓
[response] Return: {label: "attack", attack_type: "SQL Injection", ...}

---

User {requests: ["/api/data?search=test"]}
  ↓
[decode] Parse batch → items[]
  ↓
[rule] OWASP CRS check → rule_score=0, no match
  ↓
[router] Decide: blocked? NO → slow path
  ↓
[cache] Check SHA256 hash → MISS
  ↓
[RAG] Vector search: Find 3 similar past requests
       Return: [[NORMAL] /api/users, [NORMAL] /search?q=..., ...]
  ↓
[llm] Call Groq with:
      "HTTP REQUEST: /api/data?search=test
       RELATED CONTEXT (RAG):
       [NORMAL] /api/users
       [NORMAL] /search?q=test
       
       Return verdict."
  ↓
[cache_save] Save result to SHA256 cache
  ↓
[response] Return: {label: "benign", source: "llm_explainer", ...}
```

### Performance Impact of RAG

**With RAG + Full CSIC2010 Dataset:**
- Cache hit: ~100-200ms (fastest)
- Cache miss: ~1-2 seconds (RAG vector search + LLM)
- LLM receives context → Better classification accuracy
- Fewer false positives

**Without RAG (empty ChromaDB):**
- LLM receives no historical context
- May over-analyze benign requests
- Possible hallucination
- Lower quality results

### Files You Must Know

| File | Purpose | Critical? |
|------|---------|-----------|
| `backends/rag_backend.py` | ChromaDB + vector search | ⭐⭐⭐ |
| `scripts/seed_rag.py` | Load test data | ⭐⭐ |
| `scripts/seed_rag_from_csic.py` | Load real dataset | ⭐⭐⭐ |
| `nodes/nodes_cache.py` | RAG vector search called here | ⭐⭐⭐ |
| `backends/llm_backend.py` | RAG context passed here | ⭐⭐⭐ |
| `graph_app.py` | Node orchestration | ⭐⭐⭐ |
