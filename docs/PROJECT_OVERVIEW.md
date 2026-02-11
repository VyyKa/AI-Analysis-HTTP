# LangChain SOC Analyzer - Project Overview

**Last Updated:** February 11, 2026  
**Status:** ✅ Production Ready  
**Repository:** VyyKa/AI-Analysis-HTTP

---

## 📊 Project Summary

**Hybrid HTTP Request Analysis System** with Cache-First Architecture
- Combines OWASP CRS Rule Engine + LLM (Groq) + RAG (Qdrant)
- Fast path (~5ms) + Slow path (~500ms) + Cache hit (~instant)
- Production-ready with persistent storage

---

## 📁 Current Project Structure

```
LangChain/
│
├── 🔧 CORE APPLICATION (4 files)
│   ├── api.py                      # FastAPI endpoint (POST /analyze)
│   ├── graph_app.py                # LangGraph 7-node pipeline
│   ├── soc_state.py                # State schema (SOCState, SOCItem)
│   └── nodes_cache.py              # Cache check + save nodes
│
├── 📦 BACKENDS/ (6 files)
│   ├── rag_backend.py              # Qdrant + vector search + embeddings
│   ├── rule_engine.py              # OWASP CRS: 15 types, 80+ patterns
│   ├── llm_backend.py              # Groq API (llama-3.3-70b-versatile)
│   ├── llm_backend_mock.py         # Mock LLM for testing
│   ├── cache_backend.py            # Persistent file cache (pickle)
│   └── batch_decoder.py            # Request normalization
│
├── 🎯 NODES/ (5 files)
│   ├── nodes_rule.py               # Apply rule engine
│   ├── nodes_router.py             # Route: fast/slow decision
│   ├── nodes_cache_save.py         # Save results to cache
│   ├── nodes_llm.py                # LLM analysis with RAG context
│   └── nodes_response.py           # Format rich JSON output
│
├── 🔨 BUILDERS/ (2 files)
│   ├── response_builder.py         # JSON response formatter (20+ fields)
│   └── audit_logger.py             # Event logging
│
├── 🚀 SCRIPTS/ (10 files)
│   ├── seed_rag.py                 # Load 6 manual examples
│   ├── seed_rag_from_csic.py       # Load 61k CSIC2010 dataset
│   ├── inspect_chromadb.py         # View Qdrant collection contents
│   ├── check_chromadb.py           # Quick Qdrant size check
│   ├── seed_and_inspect.py         # Combined seed + inspect
│   ├── migrate_chroma_to_qdrant.py # Migrate ChromaDB data to Qdrant
│   ├── debug_cache.py              # Debug cache operations
│   ├── visualize_graph.py          # Render LangGraph diagram
│   ├── visualize_graph_simple.py   # Simplified diagram
│   └── generate_artifacts.py       # Generate test artifacts
│
├── 🧪 TESTS/ (9 files)
│   ├── test_cache_flow.py          # 4-test cache behavior (real API)
│   ├── test_cache_mock.py          # Cache tests (mock LLM)
│   ├── test_cache_simple.py        # Simple cache node test
│   ├── test_full_pipeline.py       # End-to-end pipeline test
│   ├── test_rag_search.py          # RAG search functionality test
│   ├── demo_fast_slow_paths.py     # Demo fast/slow routing
│   ├── sanity_check.py             # Basic functionality test
│   ├── test_format.py              # Output format validation
│   └── test_new_patterns.py        # Pattern detection tests
│
├── 📚 DOCS/ (12 files)
│   ├── FINAL_PROJECT_SUMMARY.txt   # Complete project overview
│   ├── CODE_TRACE_RAG_LINE_BY_LINE.md  # Line-by-line code trace
│   ├── DATA_FLOW_VISUAL.md         # Mermaid flow diagrams
│   ├── DATA_FLOW_AND_RAG_SOURCE.txt    # ASCII flow + RAG source
│   ├── RAG_DATASET_SOURCE_VI.md    # Vietnamese RAG explanation
│   ├── VISUAL_SUMMARY.md           # Quick visual reference
│   ├── FAST_SLOW_PATH_DOCS.md      # Architecture deep dive
│   ├── RESPONSE_FORMAT_DOC.md      # JSON output specification
│   ├── IMPROVEMENT_REPORT.md       # System improvements log
│   ├── SCORING_SYSTEM.md           # OWASP anomaly scoring
│   ├── SCORING_COMPARISON.md       # Score analysis
│   └── TEST_SUMMARY.md             # Test results summary
│
├── 💾 DATA & STORAGE
│   ├── qdrant (docker volume)      # Persistent Qdrant vector store
│   ├── cache_data.pkl              # Persistent file cache
│   ├── .env                        # GROQ_API_KEY
│   └── .env.example                # Template
│
├── 🎨 ARTIFACTS/
│   └── (generated diagrams: langgraph.png, langgraph.mmd)
│
├── 📄 ROOT DOCUMENTATION
│   ├── README.md                   # Main README
│   ├── CACHE_FIRST_ARCHITECTURE.md # Cache-first design document
│   ├── PROJECT_OVERVIEW.md         # This file
│   ├── QUICK_REFERENCE.md          # Command reference
│   └── PROJECT_VISUAL_SUMMARY.txt  # ASCII art summary
│
└── 🐍 PYTHON ENVIRONMENT
    └── venv_langgraph/             # Virtual environment
```

---

## 🎯 Key Features

### 1️⃣ Cache-First Architecture
```
Request → Decode → Cache Check
    ├─ HIT → Response (instant, <5ms)
    └─ MISS → Full Pipeline
        ├─ Rule Engine (OWASP CRS)
        ├─ Router (Fast/Slow decision)
        ├─ LLM + RAG (if needed on slow path)
        └─ Save to Cache → Response
```

**Actual Node Sequence:** decode → cache → rule → router → [llm] → cache_save → response

### 2️⃣ Hybrid Detection
- **Fast Path**: Rule-based blocking (~5ms)
- **Slow Path**: LLM analysis with RAG context (~500ms)
- **RAG Context**: Top-3 similar examples from Qdrant

### 3️⃣ Persistent Storage
- **Cache**: `cache_data.pkl` - File-based persistent cache
- **RAG DB**: Qdrant collection (persistent via Docker volume)
- **Survives restarts**: No need to reseed on every run

### 4️⃣ Dataset Support
- **Manual**: 6 hard-coded examples (scripts/seed_rag.py)
- **CSIC2010**: 61,792 real HTTP payloads from Hugging Face
- **Storage**: Qdrant with 384D SentenceTransformer embeddings

---

## 🔄 Complete Data Flow (Correct Node Order)

```
┌─────────────────────────────────────────────────────────────┐
│                         USER INPUT                          │
│                 {requests: ["SELECT...", ...]}              │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│  1. DECODE (batch_decoder)                                  │
│     Parse & normalize requests                              │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│  2. CACHE CHECK (nodes_cache.py)                            │
│     Check if request already analyzed                       │
└─────────────────────┬──────────┬────────────────────────────┘
                      │          │
                 CACHE HIT    CACHE MISS
                      │          │
                      │  ┌───────▼───────────────────────────┐
                      │  │  3. RULE ENGINE (nodes_rule.py)   │
                      │  │     OWASP CRS pattern matching    │
                      │  │     Output: rule_score, blocked   │
                      │  └───────┬───────────────────────────┘
                      │          │
                      │  ┌───────▼───────────────────────────┐
                      │  │  4. ROUTER (nodes_router.py)      │
                      │  │     All blocked? Fast : Slow      │
                      │  └─────┬──────────┬──────────────────┘
                      │        │          │
                      │   FAST PATH    SLOW PATH
                      │   (blocked)    (needs LLM)
                      │        │          │
                      │        │  ┌───────▼───────────────────┐
                      │        │  │  5. LLM (nodes_llm.py)    │
                      │        │  │     RAG context + Groq    │
                      │        │  └───────┬───────────────────┘
                      │        │          │
                      │  ┌─────▼──────────▼───────────────────┐
                      │  │  6. CACHE_SAVE (nodes_cache_save) │
                      │  │     Store result to cache          │
                      │  └───────┬────────────────────────────┘
                      │          │
                      └──────────┘
                                 │
┌────────────────────────────────▼─────────────────────────────┐
│  7. RESPONSE (nodes_response.py)                             │
│     Format 20+ field JSON output                             │
└────────────────────────────────┬─────────────────────────────┘
                                 │
                         ┌───────▼───────┐
                         │  JSON OUTPUT  │
                         └───────────────┘
```

**Key Points:**
- ✅ **Cache check happens FIRST** (after decode), not after router
- Cache hit → Skip everything → Go straight to response
- Cache miss → Run full pipeline (rule → router → llm/fast → cache_save)
- Fast path: Rule blocks all → Skip LLM → Save to cache
- Slow path: Needs LLM → Get RAG context → LLM analysis → Save to cache


---

## 🚀 Quick Start Guide

### 1. Setup Environment
```bash
cd "e:\DO AN MOI NHAT\LangChain"
source venv_langgraph/Scripts/activate  # Windows: venv_langgraph\Scripts\activate
```

### 2. Set API Key
```bash
# Check .env file
echo $env:GROQ_API_KEY
# Should show: gsk_7XZxR7Y9uU...
```

### 3. Seed RAG Database (First Time Only)
```bash
# Option A: Quick test (6 examples)
python scripts/seed_rag.py

# Option B: Production (61k examples, ~2-5 min)
python scripts/seed_rag_from_csic.py
```

### 4. Verify Setup
```bash
# Check RAG contents
python scripts/inspect_chromadb.py

# Check cache
python scripts/debug_cache.py

# Check Qdrant
python scripts/check_chromadb.py
```

### 5. Run Tests
```bash
# Full cache flow test (real API)
python test_cache_flow.py

# Mock LLM test (no API key needed)
python tests/test_cache_mock.py

# Simple cache test
python test_cache_simple.py

# Full pipeline test
python test_full_pipeline.py
```

### 6. Start API Server
```bash
python api.py
# Listens on http://127.0.0.1:8000
```

### 7. Test Endpoint
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"requests": ["SELECT * FROM users", "GET /api"]}'
```

---

## 📊 File Statistics

| Category | Files | Lines (approx) |
|----------|-------|----------------|
| Core App | 5 | 500 |
| Backends | 6 | 1,200 |
| Nodes | 6 | 600 |
| Builders | 2 | 400 |
| Scripts | 7 | 800 |
| Tests | 6 | 600 |
| Docs | 12 | 5,000+ |
| **TOTAL** | **44** | **~9,100** |

---

## 🔍 Key Files Explained

### Core Application
- **graph_app.py**: Main LangGraph definition with 7 nodes and conditional routing
- **soc_state.py**: TypedDict schema for state management
- **api.py**: FastAPI server with POST /analyze endpoint

### Backend Services
- **rag_backend.py**: Qdrant integration (vector storage, search, embeddings)
- **rule_engine.py**: OWASP CRS patterns (15 attack types, 80+ regex)
- **llm_backend.py**: Groq API client with RAG context passing
- **cache_backend.py**: Persistent pickle-based cache

### Graph Nodes
- **nodes_rule.py**: Apply OWASP patterns, compute anomaly score
- **nodes_router.py**: Decide fast (all blocked) or slow (needs LLM)
- **nodes_cache.py**: Check cache, if miss → RAG search
- **nodes_llm.py**: Call LLM with RAG context
- **nodes_cache_save.py**: Save results to persistent cache
- **nodes_response.py**: Format rich 20-field JSON

### Critical Scripts
- **seed_rag.py**: Load 6 manual examples (instant)
- **seed_rag_from_csic.py**: Load 61k CSIC2010 dataset (2-5 min)
- **inspect_chromadb.py**: View Qdrant collection contents
- **visualize_graph.py**: Generate LangGraph diagram

---

## 🎨 Architecture Highlights

### Cache Strategy
```python
# backends/cache_backend.py
CACHE_FILE = "cache_data.pkl"

def cache_get(text: str) -> dict | None:
    # SHA256 hash → lookup in persistent pickle file
    
def cache_set(text: str, value: dict):
    # Store full result dict to disk
```

### RAG Integration
```python
# backends/rag_backend.py
# Qdrant persistent storage: docker volume
collection = client.get_or_create_collection("soc_attacks")

def vector_search(query: str, k: int = 3):
    # Encode query → search Qdrant → return top-3
    
def rag_list_parser(results):
    # Format: "[ANOMALOUS] SQL Injection: SELECT..."
```

### Conditional Routing
```python
# graph_app.py
def route_after_rule(state: SOCState) -> str:
    if all(item.get("blocked") for item in state["items"]):
        return "fast"  # All blocked by rules
    return "slow"      # Need LLM analysis
```

---

## 🔧 Configuration

### Environment Variables
```bash
# .env
GROQ_API_KEY=your-api-key-here
QDRANT_URL=http://localhost:6333
QDRANT_COLLECTION=soc_attacks
```

### OWASP Threshold
```python
# backends/rule_engine.py
INBOUND_ANOMALY_THRESHOLD = PARANOIA_THRESHOLDS["PARANOIA_1"]  # 5
# Options: PARANOIA_1=5, PARANOIA_2=7, PARANOIA_3=10, PARANOIA_4=15
```

### LLM Model
```python
# backends/llm_backend.py
model="llama-3.3-70b-versatile"
```

### Cache Location
```python
# backends/cache_backend.py
CACHE_FILE = "cache_data.pkl"  # Change for different cache file
```

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Cache Hit | <5ms |
| Fast Path (rule block) | ~5ms |
| Slow Path (LLM + RAG) | ~500ms |
| RAG Search | ~200-300ms |
| LLM Inference | ~800-1500ms |
| Batch (100 items) | Variable (depends on path mix) |

---

## 🧪 Testing Strategy

### Test Coverage
1. **test_cache_flow.py**: 4 tests covering cache hit/miss scenarios
2. **test_cache_mock.py**: Mock LLM testing without API key
3. **test_full_pipeline.py**: End-to-end integration test
4. **test_rag_search.py**: RAG vector search validation
5. **demo_fast_slow_paths.py**: Demonstrate routing logic

### Debug Utilities
- **check_chromadb.py**: Verify Qdrant has data
- **debug_cache.py**: Inspect cache contents
- **test_cache_simple.py**: Minimal cache test

---

## 📦 Dependencies

```
langgraph          # State graph orchestration
groq               # LLM API client
qdrant-client      # Vector database client
sentence-transformers  # Embeddings (all-MiniLM-L6-v2)
fastapi            # API server
uvicorn            # ASGI server
python-dotenv      # Environment variables
datasets           # Hugging Face datasets (for CSIC2010)
```

---

## 🐛 Known Issues & Limitations

1. **Qdrant Service**: Requires Qdrant running (Docker or Cloud)
    - If service is down, RAG search will fail

2. **Cache TTL**: No expiration mechanism yet
   - Persistent cache grows indefinitely
   - Consider adding TTL in future

---

## 🔜 Future Improvements

- [ ] Add cache TTL/expiration
- [ ] Clean up duplicate files (rule_engine.py, nodes_cache.py in root)
- [ ] Update root README.md with new structure
- [ ] Add requirements.txt with pinned versions
- [ ] Docker containerization
- [ ] Prometheus metrics export
- [ ] Grafana dashboard
- [ ] CI/CD pipeline
- [ ] Rate limiting on API

---

## 📞 Resources

| Resource | Location |
|----------|----------|
| **Main Docs** | docs/FINAL_PROJECT_SUMMARY.txt |
| **Flow Diagrams** | docs/DATA_FLOW_VISUAL.md |
| **Code Trace** | docs/CODE_TRACE_RAG_LINE_BY_LINE.md |
| **Vietnamese Guide** | docs/RAG_DATASET_SOURCE_VI.md |
| **Cache Architecture** | CACHE_FIRST_ARCHITECTURE.md |
| **GitHub Repo** | https://github.com/VyyKa/AI-Analysis-HTTP |

---

## ✅ Checklist for New Developers

- [ ] Clone repo
- [ ] Setup venv: `python -m venv venv_langgraph`
- [ ] Activate: `source venv_langgraph/Scripts/activate`
- [ ] Install deps: `pip install -r requirements.txt` (create if missing)
- [ ] Set GROQ_API_KEY in .env
- [ ] Seed RAG: `python scripts/seed_rag.py`
- [ ] Verify: `python scripts/check_chromadb.py`
- [ ] Test: `python test_cache_simple.py`
- [ ] Start API: `python api.py`
- [ ] Read: docs/FINAL_PROJECT_SUMMARY.txt

---

**Last Review:** February 11, 2026  
**Maintainer:** VyyKa  
**Status:** ✅ Active Development

