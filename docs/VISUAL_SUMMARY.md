================================================================================
CẤU TRÚC HỆ THỐNG - VISUAL SUMMARY
================================================================================

1️⃣ DATASET CHO RAG
═══════════════════════════════════════════════════════════════════════════════

  SEED DATA (6 items)                CSIC2010 (61,792 items)
  ─────────────────────────          ─────────────────────────
  Manual examples                    Real HTTP payloads from HF
  scripts/seed_rag.py                scripts/seed_rag_from_csic.py
  Instant                            2-5 minutes first time
  └─→ add_rag_example()              └─→ load_dataset() + add_rag_example()
      
      ↓                                  ↓
      └──────────────────┬───────────────┘
                         ↓
              ChromaDB Collection
              "soc_attacks"
              ├─ 6 items (OR 61,792 items)
              ├─ Each: {id, doc, label, type, embedding}
              └─ In-memory (backends/rag_backend.py)


2️⃣ REQUEST PROCESSING FLOW
═══════════════════════════════════════════════════════════════════════════════

User Input: {requests: [...]}
  │
  ├─→ [DECODE] Batch parser
  │
  ├─→ [RULE] OWASP CRS engine (80+ patterns)
  │   └─ If blocked=true → FAST path
  │   └─ If blocked=false → SLOW path
  │
  ├─→ [ROUTER] Conditional branching
  │   │
  │   ├─FAST─→ [CACHE_SAVE] Save rule block
  │   │        └─→ [RESPONSE] Return verdict
  │   │
  │   └─SLOW─→ [CACHE] Check cache
  │           │
  │           ├─Hit ─→ Restore LLM output
  │           │
  │           └─Miss ─→ RAG VECTOR SEARCH (🎯 THIS IS RAG!)
  │                    ├─ Encode query → 384D vector
  │                    ├─ Search ChromaDB
  │                    ├─ Get top-3 similar + metadata
  │                    └─ Format as string
  │                         │
  │                         ├─→ [LLM] Groq API
  │                         │   ├─ Input: new request
  │                         │   ├─ Context: RAG results
  │                         │   └─ Output: verdict
  │                         │
  │                         ├─→ [CACHE_SAVE] Store result
  │
  └─→ [RESPONSE] Final JSON output


3️⃣ RAG OPERATION DETAIL
═══════════════════════════════════════════════════════════════════════════════

REQUEST COMES IN
  │
  └─ NOT BLOCKED by rule engine
      │
      └─ NEW (not in cache)
          │
          └─RAG PROCESS:
              │
              1. vector_search(query)
              │  INPUT: Request text
              │  PROCESS:
              │    ├─ model.encode(query) → [0.1, 0.3, ... 384D]
              │    ├─ ChromaDB.query(embeddings=[...], n=3)
              │    └─ Get top-3 stored items with metadata
              │  OUTPUT: List[{raw_request, label, attack_type}]
              │
              2. rag_list_parser(results)
              │  INPUT: List of 3 items
              │  FORMAT: "[LABEL] TYPE: request_text\n[LABEL] TYPE: ..."
              │  OUTPUT: String for LLM context
              │
              3. llm_analyze(query, rag_context)
              │  INPUT:
              │    ├─ query: new request
              │    └─ rag_context: formatted string from step 2
              │  PROCESS:
              │    ├─ Build messages with RAG context in prompt
              │    ├─ Call Groq API
              │    └─ Get LLM verdict
              │  OUTPUT: {analysis: "...", model: "..."}
              │
              4. Save to cache
                 KEY: SHA256(query)
                 VALUE: Full result dict


4️⃣ FILE ORGANIZATION
═══════════════════════════════════════════════════════════════════════════════

PROJECT ROOT
│
├─ graph_app.py                     Main StateGraph definition
├─ soc_state.py                     State schema (TypedDict)
│
├─ backends/                        ← Core logic
│  ├─ rag_backend.py               🎯 ChromaDB + vector search
│  ├─ rule_engine.py               Pattern matching
│  ├─ llm_backend.py               Groq API
│  ├─ cache_backend.py             Hash cache
│  └─ batch_decoder.py             Input parsing
│
├─ nodes/                           ← Graph nodes
│  ├─ nodes_rule.py                Apply rules
│  ├─ nodes_cache.py               🎯 RAG search called here
│  ├─ nodes_llm.py                 🎯 RAG context used here
│  ├─ nodes_router.py              Route decision
│  ├─ nodes_cache_save.py          Save results
│  └─ nodes_response.py            Format output
│
├─ builders/                        ← Utilities
│  ├─ response_builder.py          JSON formatter
│  └─ audit_logger.py              Event logging
│
├─ scripts/                         ← Utilities
│  ├─ seed_rag.py                  🎯 Load 6 manual examples
│  ├─ seed_rag_from_csic.py        🎯 Load 61k CSIC2010 dataset
│  ├─ seed_and_inspect.py          Seed + view combined
│  ├─ inspect_chromadb.py          View RAG contents
│  └─ visualize_graph.py           Render graph diagram
│
├─ tests/                           ← Unit tests
│  ├─ test_cache_flow.py           Cache behavior (real API)
│  └─ test_cache_mock.py           Cache behavior (mock LLM)
│
├─ docs/                            ← Documentation
│  ├─ README.md                    Main doc
│  ├─ FAST_SLOW_PATH_DOCS.md      Architecture
│  ├─ DATA_FLOW_VISUAL.md          This flow
│  ├─ CODE_TRACE_RAG_...md         Line-by-line code mapping
│  └─ RAG_DATASET_SOURCE_VI.md    Vietnamese explanation
│
└─ venv_langgraph/                 Python environment


5️⃣ KEY FILES INTERACTION
═══════════════════════════════════════════════════════════════════════════════

RAG DATASET:
  seed_rag.py ─────┐
                   ├─→ backends/rag_backend.py
  seed_rag_from_csic.py ─┘
                        add_rag_example()
                        ↓
                        ChromaDB collection "soc_attacks"


RAG USAGE:
  graph_app.py (7 nodes)
    ├─ nodes/nodes_cache.py
    │  └─ vector_search()  ← from rag_backend.py
    │    └─ rag_list_parser()  ← from rag_backend.py
    │
    └─ nodes/nodes_llm.py
       └─ llm_analyze(query, rag_context)  ← rag_context från cache.py
          └─ backends/llm_backend.py


VERIFICATION:
  scripts/inspect_chromadb.py  ← View what's stored
  scripts/seed_and_inspect.py  ← Seed + view in one


6️⃣ DECISION TREE
═══════════════════════════════════════════════════════════════════════════════

                      USER REQUEST
                          │
                    [Decode Parser]
                          │
                    [Rule Engine] ← OWASP CRS
                          │
                      blocked?
                      /       \
                    YES        NO
                     │          │
                  FAST       [Cache Check]
                  PATH        │
                   │      HIT?
              Save         /   \
              Cache       /     \
                │        YES    NO
                │         │      │
                │      Use    [RAG] ← 🎯 VECTOR SEARCH
                │     Cache    │
                │      │    Encode+Query
                │      │      │
                │      │   [LLM] with RAG context
                │      │      │
                │      └──┬───┘
                │         │
                └────[Cache Save]
                     │
                  [Response] ← Final JSON
                     │
                  OUTPUT


7️⃣ QUICK VERIFICATION COMMANDS
═══════════════════════════════════════════════════════════════════════════════

Check RAG Dataset Source:
  cat backends/rag_backend.py       # Line 3: ChromaDB init
  cat scripts/seed_rag.py           # Manual examples
  cat scripts/seed_rag_from_csic.py # CSIC2010 loader

Check RAG Usage Points:
  grep -n "vector_search" nodes/nodes_cache.py       # Line 18
  grep -n "rag_context" nodes/nodes_llm.py          # Line 14
  grep -n "rag_context" backends/llm_backend.py     # Line 56

Check ChromaDB Structure:
  python scripts/seed_and_inspect.py  # Seed + view

Run Complete Flow:
  python tests/test_cache_flow.py     # Full test with Groq
  python tests/test_cache_mock.py     # Full test with mock

Start API:
  python api.py                       # Start server on port 8000


8️⃣ RAG IMPACT
═══════════════════════════════════════════════════════════════════════════════

WITH RAG (After seeding):
  ✅ LLM sees example attacks/normal requests
  ✅ Better pattern recognition
  ✅ Lower false positive rate
  ✅ Contextual analysis
  ✅ Faster decisions (from example similarity)

WITHOUT RAG (Empty ChromaDB):
  ❌ LLM gets no context
  ❌ May over-analyze benign requests
  ❌ Possible hallucination
  ❌ Less reliable classification
  ❌ Worse performance

⚠️ MUST SEED before using:
   python scripts/seed_rag.py              # OR
   python scripts/seed_rag_from_csic.py


9️⃣ PERFORMANCE
═══════════════════════════════════════════════════════════════════════════════

Rule-BLOCKED (Fast Path):
  Rule check → Save → Response = ~50ms

Cache HIT:
  Check cache → Restore → Response = ~100-200ms

Cache MISS (RAG + LLM):
  Vector search: ~200-300ms
  LLM inference: ~800-1500ms
  Total: ~1-2 seconds

💡 Optimization: Cache hit rate improves over time with repeated requests


🔟 DEPLOYMENT CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

□ Check GROQ_API_KEY in .env file
□ Run: python scripts/seed_rag.py (or seed_rag_from_csic.py)
□ Verify: python scripts/seed_and_inspect.py
□ Test: python tests/test_cache_mock.py
□ Deploy: python api.py

================================================================================
