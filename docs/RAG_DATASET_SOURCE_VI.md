================================================================================
FINAL VERIFICATION: COMPLETE SYSTEM OVERVIEW
================================================================================

🎯 WHERE RAG GETS ITS DATASET
================================================================================

Question: Ụa RAG lấy dataset ở đâu?
Answer: RAG lấy từ 2 nơi (bạn chọn 1):

┌────────────────────────────────────────────────────────────────────────────┐
│ SOURCE 1: MANUAL SEED (Nhanh, dùng cho test)                              │
├────────────────────────────────────────────────────────────────────────────┤
│ File: scripts/seed_rag.py                                                  │
│                                                                             │
│ Dữ liệu:                                                                   │
│   Anomalous (3 cái):                                                       │
│   • "id=1 UNION SELECT password FROM users"     → SQL Injection            │
│   • "<script>alert(1)</script>"                 → XSS                      │
│   • "../../etc/passwd"                          → Path Traversal          │
│                                                                             │
│   Normal (3 cái):                                                          │
│   • "/api/users"                                → Normal                   │
│   • "/search?q=python"                          → Normal                  │
│   • "/home"                                     → Normal                   │
│                                                                             │
│ Lưu vào: ChromaDB in-memory collection tên "soc_attacks"                  │
│                                                                             │
│ Cách chạy:                                                                 │
│   cd "e:\DO AN MOI NHAT\LangChain"                                        │
│   python scripts/seed_rag.py                                               │
│                                                                             │
│ Thời gian: <1 giây                                                         │
└────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────┐
│ SOURCE 2: CSIC2010 DATASET (Lớn, dùng cho production)                     │
├────────────────────────────────────────────────────────────────────────────┤
│ File: scripts/seed_rag_from_csic.py                                        │
│                                                                             │
│ Dataset:                                                                    │
│   Tên: CSIC2010_dataset_classification                                     │
│   Nơi: Hugging Face Hub                                                    │
│   URL: https://huggingface.co/datasets/nquangit/CSIC2010_dataset_...       │
│                                                                             │
│ Dữ liệu:                                                                   │
│   • 61,792 HTTP request payloads                                           │
│   • Mỗi request có label: "normal" hoặc attack type                        │
│   • Thực tế từ web app testing                                             │
│                                                                             │
│ Cách lấy:                                                                  │
│   1. Python load_dataset() từ Hugging Face API                            │
│   2. Auto-detect columns: request, label                                   │
│   3. Vòng lặp qua 61,792 items                                             │
│   4. Gọi add_rag_example(text, is_anomalous, attack_type)                 │
│   5. Lưu tất cả vào ChromaDB collection "soc_attacks"                     │
│                                                                             │
│ Cách chạy:                                                                 │
│   cd "e:\DO AN MOI NHAT\LangChain"                                        │
│   pip install datasets  (nếu chưa có)                                      │
│   python scripts/seed_rag_from_csic.py                                     │
│                                                                             │
│ Thời gian: ~2-5 phút (tùy tốc độ mạng)                                    │
└────────────────────────────────────────────────────────────────────────────┘

📍 NƠI STORES DỮ LIỆU: backends/rag_backend.py
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   client = chromadb.Client()                 # ← In-memory database        │
│   collection = client.get_or_create_collection("soc_attacks")             │
│                                              # ← Collection name           │
│                                                                             │
│   STRUCTURE CỦA MỖI ITEM:                                                  │
│   {                                                                         │
│     "id": "f1290ac8a7905b4b4cc68d766a3dbfc8c46ab8b1...",  # SHA256 hash   │
│     "document": "id=1 UNION SELECT password FROM users",                  │
│     "metadata": {                                                          │
│       "label": "anomalous",                   # "normal" hoặc "anomalous"  │
│       "attack_type": "SQL Injection"          # Loại attack               │
│     },                                                                     │
│     "embedding": [0.234, 0.567, ..., 0.891]  # 384D vector               │
│   }                                                                        │
│                                              # ← Từ SentenceTransformer   │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘


🔄 FLOW: RAG KHI NÀO ĐƯỢC DÙNG?
================================================================================

User gửi request → qua rule engine → không bị chặn → vào SLOW PATH

SLOW PATH:
  ├─ Node 4 (cache check): 
  │  └─ Kiểm tra: Đã xử lý request này chưa?
  │     ├─ Có (cache HIT): Lấy kết quả từ cache, SKIP LLM
  │     └─ Không (cache MISS):
  │           ↓
  │        RAG VECTOR SEARCH ← DÙNG DỮ LIỆU TỪ SEED
  │           ↓
  │        1. Mã hóa request mới bằng SentenceTransformer
  │        2. Tìm 3 request tương tự nhất trong ChromaDB
  │        3. Lấy metadata: label, attack_type
  │        4. Format thành string:
  │           "[ANOMALOUS] SQL Injection: id=1 UNION...\n[NORMAL] /api/..."
  │        5. Lưu vào item["rag_context"]
  │           ↓
  ├─ Node 5 (LLM):
  │  └─ Gửi tới Groq LLM:
  │     System: "You are SOC analyst..."
  │     User: "HTTP REQUEST: {new_request}
  │            RELATED CONTEXT (RAG):
  │            {rag_context}
  │            Return verdict."
  │           ↓
  └─ Node 6 (cache save):
     └─ Lưu kết quả vào cache để lần sau nhanh hơn


🔍 INSPECT DỮ LIỆU TRONG RAG
================================================================================

Cách 1: Xem sau khi seed
  python scripts/seed_and_inspect.py
  → Hiển thị: Tất cả items, metadata, statistics

Cách 2: Xem mà không seed (empty)
  python scripts/inspect_chromadb.py
  → Hiển thị: "Collection is empty" (vì init process này tạo instance mới)

⚠️  Important: ChromaDB in-memory nên reset mỗi lần python process khác

Giải pháp: Chạy seed + inspect trong 1 script:
  python scripts/seed_and_inspect.py


✅ FILE CHECKLIST - TOÀN BỘ HỆ THỐNG
================================================================================

CORE LOGIC (7 files):
  ✅ graph_app.py                 - Main StateGraph definition
  ✅ soc_state.py                 - TypedDict schema

BACKENDS (6 files):
  ✅ backends/rag_backend.py      - ChromaDB + vector search ← RAG IS HERE
  ✅ backends/rule_engine.py      - OWASP CRS patterns
  ✅ backends/llm_backend.py      - Groq LLM
  ✅ backends/llm_backend_mock.py - Mock LLM (no API key)
  ✅ backends/cache_backend.py    - SHA256 cache
  ✅ backends/batch_decoder.py    - Input parsing

NODES (6 files):
  ✅ nodes/nodes_rule.py          - Apply rules
  ✅ nodes/nodes_router.py        - Route decision
  ✅ nodes/nodes_cache.py         - Cache check + RAG SEARCH ← RAG CALLED HERE
  ✅ nodes/nodes_llm.py           - LLM analysis with RAG context
  ✅ nodes/nodes_cache_save.py    - Save to cache
  ✅ nodes/nodes_response.py      - Format output

BUILDERS (2 files):
  ✅ builders/response_builder.py - JSON formatter
  ✅ builders/audit_logger.py     - Event logging

SCRIPTS (4 files):
  ✅ scripts/seed_rag.py          - Seed manual examples ← RAG DATASET 1
  ✅ scripts/seed_rag_from_csic.py - Seed CSIC2010 ← RAG DATASET 2
  ✅ scripts/inspect_chromadb.py  - View RAG data
  ✅ scripts/seed_and_inspect.py  - Seed + view combined

TESTS (2 files):
  ✅ tests/test_cache_flow.py     - Cache hit/miss tests
  ✅ tests/test_cache_mock.py     - Tests with mock LLM

DOCUMENTATION (3 files):
  ✅ docs/README.md               - Main documentation
  ✅ docs/FAST_SLOW_PATH_DOCS.md - Architecture docs
  ✅ docs/DATA_FLOW_VISUAL.md     - This document


⚠️  IMPORTANT NOTES
================================================================================

1. ChromaDB IN-MEMORY:
   • Mỗi python process mới = ChromaDB instance mới (rỗng)
   • Phải RUN seed_rag.py trước khi dùng system
   • Nếu muốn persistent: Đổi thành PersistentClient(path="./chroma_data")

2. Groq API Key:
   • Cần GROQ_API_KEY environment variable
   • Nếu không có: Dùng test_cache_mock.py thay vì test_cache_flow.py
   • File .env sẵn có: GROQ_API_KEY=your_key_here

3. CSIC2010 Dataset:
   • Requires 'datasets' package: pip install datasets
   • Auto-download từ Hugging Face first time (slow)
   • Để tách biệt, có thể dùng seed_rag.py cho test

4. SentenceTransformer Model:
   • First run: Download ~100MB model "all-MiniLM-L6-v2"
   • After: Cached locally, fast loading


📊 QUICK STATS
================================================================================

Manual Dataset (seed_rag.py):
  Items: 6
  Storage: Instant
  Anomalous: 3
  Normal: 2

CSIC2010 Dataset (seed_rag_from_csic.py):
  Items: 61,792
  Storage: ~2-5 minutes
  Typical: Mix of normal + 15 attack types
  Quality: Production-ready

ChromaDB Collection:
  Name: "soc_attacks"
  Embedding dimension: 384 (all-MiniLM-L6-v2)
  Indexed: Vector similarity search

Cache Stats:
  Type: In-memory Hash (SHA256)
  TTL: None (persists until process exits)
  Hit ratio: Depends on workload
  Cost: No external dependency (fast)


🚀 TYPICAL USAGE SEQUENCE
================================================================================

Session 1: Initial Setup
  $ cd "e:\DO AN MOI NHAT\LangChain"
  $ source venv_langgraph/Scripts/activate
  $ python scripts/seed_rag.py              # Load rag data
  $ python scripts/seed_and_inspect.py      # Verify
  $ python tests/test_cache_mock.py         # Test without API key

Session 2: Full System Test
  $ python scripts/seed_rag_from_csic.py    # Load 61k items (slow)
  $ python tests/test_cache_flow.py         # Real Groq API test

Session 3: Production Use
  $ python api.py                           # Start server
  $ curl -X POST http://127.0.0.1:8000/analyze \
    -H "Content-Type: application/json" \
    -d '{"requests": ["GET /users"]}'


🔑 KEY TAKEAWAY
================================================================================

RAG DATASET SOURCES:
  1. scripts/seed_rag.py → Hard-coded 6 examples (test)
  2. scripts/seed_rag_from_csic.py → Hugging Face 61k real payloads (prod)

WHERE STORED:
  → ChromaDB in-memory "soc_attacks" collection (backends/rag_backend.py)

USED BY:
  → nodes/nodes_cache.py (vector_search When cache miss)
  → nodes/nodes_llm.py (passed as context to Groq LLM)

IMPACT:
  → LLM gets examples of similar attacks/normal requests
  → Better classification accuracy
  → Fewer false positives

================================================================================
