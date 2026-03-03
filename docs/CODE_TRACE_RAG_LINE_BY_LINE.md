================================================================================
CODE TRACING: WHERE RAG IS USED (Line by Line)
================================================================================

🎯 RAG DATASET SEEDING
================================================================================

Step 1: Load Manual Examples
┌─────────────────────────────────────────────────────────────────────────┐
│ File: scripts/seed_rag.py (6 items)                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ from backends.rag_backend import add_rag_example  ← Import RAG backend │
│                                                                         │
│ add_rag_example("id=1 UNION SELECT ...", is_anomalous=True, ...) ← A  │
│ add_rag_example("<script>...", is_anomalous=True, ...)           ← D  │
│ add_rag_example("../../etc/passwd", is_anomalous=True, ...)      ← D  │
│ add_rag_example("/api/users", is_anomalous=False)                ← N  │
│ add_rag_example("/search?q=...", is_anomalous=False)             ← N  │
│ add_rag_example("/home", is_anomalous=False)                     ← N  │
│                                                                         │
│ (A = Anomalous, D = Detected, N = Normal)                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 2: What add_rag_example() Does
┌─────────────────────────────────────────────────────────────────────────┐
│ File: backends/rag_backend.py (lines 15-31)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ def add_rag_example(text: str, is_anomalous: bool, attack_type: str):  │
│     emb = model.encode(text).tolist()  ← Encode to 384D vector        │
│                                         (SentenceTransformer)          │
│                                                                         │
│     doc_id = _make_doc_id(text)        ← SHA256(text)                 │
│                                         Prevent duplicates              │
│                                                                         │
│     collection.add(                                                    │
│         documents=[text],                  ← Store request text       │
│         metadatas=[{                       ← Store metadata           │
│             "label": "anomalous" if is_anomalous else "normal",      │
│             "attack_type": attack_type or "normal"                   │
│         }],                                                            │
│         embeddings=[emb],                  ← Store 384D vector       │
│         ids=[doc_id]                       ← Store SHA256 ID         │
│     )                                                                  │
│                                                                         │
│ ChromaDB collection = {                                                │
│   "soc_attacks": [                                                     │
│     {id: f129..., doc: "SELECT...", meta: {...}, emb: [...]},        │
│     {id: 5c14..., doc: "<script>...", meta: {...}, emb: [...]},      │
│     ...                                                                │
│   ]                                                                    │
│ }                                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 3: Load Large Dataset (61k items)
┌─────────────────────────────────────────────────────────────────────────┐
│ File: scripts/seed_rag_from_csic.py (lines 12-45)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ dataset = load_dataset("nquangit/CSIC2010_dataset_classification",    │
│                        split="train")  ← Download from Hugging Face   │
│                                           (61,792 items)               │
│                                                                         │
│ for idx, row in enumerate(dataset):                                    │
│     request = row.get(col_request, "")  ← Get HTTP request text      │
│     label_value = row.get(col_label, "Unknown")  ← Get label         │
│                                                                         │
│     is_anomalous = label_str != "normal"  ← Detect anomalous        │
│                                                                         │
│     add_rag_example(request, is_anomalous, label_value)              │
│     ↓                                                                  │
│     (Same as Step 2: encode → hash → store in ChromaDB)              │
│                                                                         │
│ After: 61,792 items in same "soc_attacks" collection                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


🔍 RAG VECTOR SEARCH WHEN USED
================================================================================

Context: Request không bị rule engine chặn → Slow path

Step 1: Cache Check Node
┌─────────────────────────────────────────────────────────────────────────┐
│ File: graph_app.py (Line 32)                                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ graph.add_node("cache", cache_router_node)                            │
│ ↓ Từ nodes/nodes_cache.py                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 2: Cache Router Node - Where RAG is Called
┌─────────────────────────────────────────────────────────────────────────┐
│ File: nodes/nodes_cache.py (complete)                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ from backends.cache_backend import cache_get                           │
│ from backends.rag_backend import vector_search, rag_list_parser       │
│                                                                         │
│ def cache_router_node(state: SOCState) -> SOCState:                   │
│     for item in state["items"]:                                        │
│         if item["blocked"]:  ← Skip nếu đã bị block bởi rule engine   │
│             continue                                                   │
│                                                                         │
│         query = item["raw_request"]  ← Get request text               │
│                                                                         │
│         # 1. Cache check                                               │
│         cached_result = cache_get(query)  ← SHA256 lookup             │
│         if cached_result:                                              │
│             item["cache_hit"] = True                                   │
│             item["llm_output"] = cached_result.get("llm_output")      │
│             continue  ← Skip RAG + LLM, lấy từ cache                 │
│                                                                         │
│         # 2. Cache MISS → RAG VECTOR SEARCH ← THIS IS IT!            │
│         search_results = vector_search(query)  ← CALL RAG BACKEND    │
│         rag_context = rag_list_parser(search_results)                │
│         item["rag_context"] = rag_context                             │
│                                                                         │
│     return state                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 3: Vector Search Function
┌─────────────────────────────────────────────────────────────────────────┐
│ File: backends/rag_backend.py (lines 36-53)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ def vector_search(query: str, k: int = 3):  ← Find top-3 similar     │
│                                                                         │
│     emb = model.encode(query).tolist()  ← Encode new request using   │
│                                           SentenceTransformer         │
│                                           → 384D vector               │
│                                                                         │
│     res = collection.query(                ← ChromaDB similarity search│
│         query_embeddings=[emb],            ← 384D embedding            │
│         n_results=k                        ← Top 3 results             │
│     )                                                                  │
│                                                                         │
│     results = []                                                       │
│     for doc, meta in zip(res["documents"][0], res["metadatas"][0]):   │
│         results.append({                                               │
│             "raw_request": doc,            ← Stored request text     │
│             "label": meta.get("label"),    ← "normal"/"anomalous"    │
│             "attack_type": meta.get("attack_type")  ← Attack type    │
│         })                                                            │
│     return results                          ← List of 3 most similar  │
│                                                                         │
│ Example output:                                                        │
│ [                                                                      │
│   {"raw_request": "SELECT * FROM ...", "label": "anomalous",         │
│    "attack_type": "SQL Injection"},                                   │
│   {"raw_request": "/api/users", "label": "normal",                   │
│    "attack_type": "normal"},                                          │
│   {"raw_request": "/search?q=test", "label": "normal",               │
│    "attack_type": "normal"}                                           │
│ ]                                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 4: Format RAG Context for LLM
┌─────────────────────────────────────────────────────────────────────────┐
│ File: backends/rag_backend.py (lines 55-61)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ def rag_list_parser(results: list[dict]) -> str:                     │
│     if not results:                                                    │
│         return ""                                                      │
│     return "\n".join(                                                  │
│         f"[{r['label'].upper()}] {r['attack_type']}: {r['raw_request']}│
│         for r in results                                              │
│     )                                                                  │
│                                                                         │
│ Output string:                                                         │
│ """                                                                    │
│ [ANOMALOUS] SQL Injection: SELECT * FROM ...                         │
│ [NORMAL] normal: /api/users                                           │
│ [NORMAL] normal: /search?q=test                                       │
│ """                                                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


💬 RAG CONTEXT PASSED TO LLM
================================================================================

Step 1: Router decides slow path, then RAG node runs
┌─────────────────────────────────────────────────────────────────────────┐
│ File: nodes/nodes_rag.py (new)                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ After rule_engine & router have finalized ``blocked``/``fast_decision``,│
│ only items routed to the slow path will be fed into rag_node.          │
│                                                                         │
│ item["rag_context"] = rag_list_parser(search_results)  ← Set in state │
│                                                                         │
│ (vector search executed only when LLM analysis is anticipated)         │
│                                                                         │
│ State now has:                                                         │
│ item = {                                                               │
│   "raw_request": "/api/data?search=test",                           │
│   "rule_score": 0,                                                    │
│   "blocked": False,                                                   │
│   "route": "slow",                                                  │
│   "rag_context": "[ANOMALOUS] SQL Injection: SELECT...\n[NORMAL]...", │
│ }                                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


Step 2: Cache Node Reads (but no longer sets) ``rag_context``
┌─────────────────────────────────────────────────────────────────────────┐
│ File: nodes/nodes_cache.py                                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ # Cache lookup only – rag_context is expected to exist already          │
│                                                                         │
│ State continues: already contains rag_context from previous node        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


Step 2: Cache Node Reads (but no longer sets) ``rag_context``
┌─────────────────────────────────────────────────────────────────────────┐
│ File: nodes/nodes_cache.py                                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ # Cache lookup only – rag_context is expected to exist already          │
│                                                                         │
│ State continues: already contains rag_context from previous node        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 2: LLM Node Uses RAG Context
┌─────────────────────────────────────────────────────────────────────────┐
│ File: graph_app.py (line 33)                                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ graph.add_node("llm", llm_node)                                        │
│ ↓ Từ nodes/nodes_llm.py                                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 3: LLM Node Implementation
┌─────────────────────────────────────────────────────────────────────────┐
│ File: nodes/nodes_llm.py (complete)                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ from backends.llm_backend import llm_analyze                           │
│                                                                         │
│ def llm_node(state: SOCState) -> SOCState:                            │
│     for item in state["items"]:                                        │
│         if item["blocked"]:  ← Skip đã bị block                       │
│             continue                                                   │
│                                                                         │
│         if item["cache_hit"]:  ← Skip đã cache hit                    │
│             continue                                                   │
│                                                                         │
│         if item["final_msg"]:  ← Skip đã có kết quả                  │
│             continue                                                   │
│                                                                         │
│         result = llm_analyze(                  ← Call LLM with RAG    │
│             query=item["raw_request"],                                │
│             rag_context=item["rag_context"]    ← PASS RAG CONTEXT!   │
│         )                                                              │
│                                                                         │
│         item["llm_output"] = result                                    │
│         item["final_msg"] = result["analysis"]                         │
│                                                                         │
│     return state                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Step 4: LLM Backend Receives RAG Context
┌─────────────────────────────────────────────────────────────────────────┐
│ File: backends/llm_backend.py (lines 37-77)                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ def llm_analyze(query: str, rag_context: str) -> dict:               │
│     messages = [                                                       │
│         {                                                              │
│             "role": "system",                                          │
│             "content": SYSTEM_PROMPT,  ← "You are SOC analyst..."    │
│         },                                                             │
│         {                                                              │
│             "role": "user",                                            │
│             "content": f"""                                            │
│ HTTP REQUEST:                                                          │
│ {query}                ← New request                                    │
│                                                                         │
│ RELATED CONTEXT (RAG):                                                 │
│ {rag_context}          ← RAG output ← 🎯 THIS IS IT!                 │
│                                                                         │
│ Return a concise security verdict.                                     │
│ """                                                                    │
│         },                                                             │
│     ]                                                                  │
│                                                                         │
│     completion = client.chat.completions.create(  ← Call Groq API    │
│         model="llama-3.3-70b-versatile",                              │
│         messages=messages,                                             │
│         temperature=0.2,                                               │
│         max_tokens=150,                                                │
│     )                                                                  │
│                                                                         │
│     verdict = completion.choices[0].message.content.strip()           │
│                                                                         │
│     return {                                                           │
│         "analysis": verdict,                                           │
│         "model": "llama-3.3-70b-versatile",                           │
│     }                                                                  │
│                                                                         │
│ LLM prompt:                                                            │
│ ───────────────────────────────────────────────────────────            │
│ HTTP REQUEST:                                                          │
│ /api/data?search=test                                                 │
│                                                                         │
│ RELATED CONTEXT (RAG):                                                 │
│ [ANOMALOUS] SQL Injection: SELECT * FROM users                       │
│ [NORMAL] normal: /api/users                                           │
│ [NORMAL] normal: /search?q=test                                       │
│                                                                         │
│ Return a concise security verdict.                                     │
│ ───────────────────────────────────────────────────────────            │
│                                                                         │
│ LLM Response:                                                          │
│ "Benign request – no malicious intent detected.                       │
│  Similar to legitimate /api/users endpoint, not injection attempt."    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


🔄 COMPLETE FLOW SUMMARY
================================================================================

User Request → Rule Engine (no match) → Cache Miss
           ↓
        vector_search()  ← Query: new request text
           ↓
    SentenceTransformer.encode()  ← 384D embedding
           ↓
    ChromaDB.query() on "soc_attacks"  ← Search stored embeddings
           ↓
    Return top-3 similar items with metadata (label, attack_type)
           ↓
    rag_list_parser()  ← Format as string
           ↓
    Set item["rag_context"]
           ↓
    llm_node() → llm_analyze(query, rag_context)
           ↓
    Groq API Call with RAG in prompt
           ↓
    Cache Save → Response


📊 EXAMPLE: Complete Request Flow With RAG
================================================================================

Input:
  Request: "/api/data?search=union%20select%201,2,3"

Step 1: Rule Engine
  Pattern matched: SQL patterns detected
  rule_score: 4 (not high enough to block automatically)
  blocked: false
  → Goes to SLOW path

Step 2: Cache Check
  SHA256("/api/data?search=union%20select%201,2,3") = abc123...
  Cache lookup: NO MATCH
  → Cache MISS

Step 3: RAG Vector Search
  Encode: "/api/data?search=union%20select%201,2,3" → 384D vector
  ChromaDB query: Find 3 closest embeddings
  Result:
    1. {doc: "id=1 UNION SELECT password FROM users", 
        label: "anomalous", type: "SQL Injection"}
    2. {doc: "/api/users", label: "normal"}
    3. {doc: "/search?q=test", label: "normal"}
  
  Format:
    "[ANOMALOUS] SQL Injection: id=1 UNION SELECT password FROM users
     [NORMAL] normal: /api/users
     [NORMAL] normal: /search?q=test"

Step 4: LLM Prompt
  System: "You are SOC analyst. No guessing..."
  User: "HTTP REQUEST: /api/data?search=union%20select%201,2,3
         RELATED CONTEXT (RAG):
         [ANOMALOUS] SQL Injection: id=1 UNION SELECT password FROM users
         [NORMAL] normal: /api/users
         [NORMAL] normal: /search?q=test
         Return verdict."

Step 5: LLM Response
  "Suspicious request – contains SQL injection pattern (UNION SELECT).
   Matches known SQL injection template from training context."

Step 6: Cache Save
  Key: abc123...
  Value: {llm_output: {...}, attack_type: "SQL Injection", ...}

Step 7: Response
  label: "attack"
  attack_type: "SQL Injection"
  source: "llm_explainer"
  confidence: 0.95


================================================================================
END OF CODE TRACE
================================================================================
