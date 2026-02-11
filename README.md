# LangChain SOC Analyzer

**Hybrid HTTP Request Analysis System** using OWASP CRS Rule Engine + LLM (LangGraph) with a Cache-First Architecture.

A production-ready security analysis pipeline that combines:
- **Cache-First**: Instant responses for previously seen requests.
- **Fast Path**: Rule-based detection (~5ms) for obvious attacks.
- **Slow Path**: LLM analysis (~500ms) for complex/unknown patterns.
- **Rich Output**: Explainable decisions with evidence & recommendations.

## Features

✅ **Cache-First Performance**
- Persistent caching of results to provide instant analysis for repeated requests.

✅ **Hybrid Architecture**
- **Fast path**: Rule engine blocks obvious attacks immediately.
- **Slow path**: LLM analyzes ambiguous/unknown patterns, enriched with RAG.
- Seamless fallback for pattern misses.

✅ **RAG-Enhanced Analysis**
- Uses a persistent Qdrant vector store for Retrieval-Augmented Generation.
- Enriches LLM context with similar examples from the `CSIC2010` dataset.

✅ **Explainable & Rich Output**
- Provides evidence, observed patterns, and severity scores.
- Suggests actions (block/log/monitor/allow).
- Includes learning notes for security education.

✅ **Comprehensive Attack Detection**
- Detects a wide range of attack types including SQL Injection, XSS, Command Injection, and more, based on the OWASP Core Rule Set.

## Architecture

The pipeline is designed as a state machine using LangGraph. It processes incoming HTTP requests through a series of nodes, each responsible for a specific task. The cache-first approach significantly speeds up the analysis by immediately returning results for known requests.

### System Flow Diagram

![LangGraph Flow](artifacts/langgraph.png)

### Project Structure

```
LangChain/
├── api.py                  # FastAPI endpoint (POST /analyze)
├── graph_app.py            # Main LangGraph 7-node pipeline
├── soc_state.py            # State schema (SOCState, SOCItem)
├── nodes_cache.py          # Cache check + save nodes
├── backends/               # Backend services (6 files)
│   ├── rag_backend.py      # Qdrant + vector search
│   ├── rule_engine.py      # OWASP CRS patterns
│   ├── llm_backend.py      # Groq LLM integration
│   ├── cache_backend.py    # Persistent file cache
│   └── ...
├── nodes/                  # LangGraph nodes (5 files)
│   ├── nodes_rule.py       # Rule engine node
│   ├── nodes_router.py     # Fast/slow router
│   ├── nodes_llm.py        # LLM analysis node
│   └── ...
├── builders/               # Response builders (2 files)
├── scripts/                # Utility scripts (10 files)
│   ├── seed_rag.py         # Seed RAG database
│   ├── seed_rag_from_csic.py  # Seed from CSIC2010
│   ├── visualize_graph.py  # Generate graph diagram
│   └── ...
├── tests/                  # Test suites (9 files)
├── docs/                   # Documentation (16 files)
└── venv_langgraph/         # Virtual environment
```

### 📚 Documentation

- **[PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md)** - Complete project guide, architecture, and file reference
- **[QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md)** - Command reference for daily workflows
- **[CACHE_FIRST_ARCHITECTURE.md](docs/CACHE_FIRST_ARCHITECTURE.md)** - Cache-first design deep dive
- **[PROJECT_VISUAL_SUMMARY.txt](docs/PROJECT_VISUAL_SUMMARY.txt)** - ASCII art visual summary

## RAG Dataset Setup

The system uses **Retrieval Augmented Generation (RAG)** to provide contextual examples to the LLM. This requires seeding a local Qdrant vector store from the `nquangit/CSIC2010_dataset_classification` dataset on Hugging Face.

**Setup Steps:**

1.  **Start Qdrant (local Docker):**
  ```bash
  docker compose up -d
  ```

2.  **Activate virtual environment:**
    ```bash
    # On Windows:
    venv_langgraph\Scripts\activate
    # On macOS/Linux:
    # source venv_langgraph/bin/activate
    ```

3.  **Run the seeding script:**
    ```bash
    # Quick test (6 examples):
    python scripts/seed_rag.py
    
    # Full dataset (61,792 items, ~2-5 min):
    python scripts/seed_rag_from_csic.py
    ```
    This will populate the local Qdrant collection.

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/VyyKa/AI-Analysis-HTTP.git
cd AI-Analysis-HTTP
python -m venv venv_langgraph
# On Windows:
venv_langgraph\Scripts\activate
# On macOS/Linux:
# source venv_langgraph/bin/activate
pip install -r requirements.txt
```

### 2. Set Environment Variables

Create a `.env` file in the root directory and add your Groq API key:
```
GROQ_API_KEY="your-groq-api-key"
QDRANT_URL="http://localhost:6333"
QDRANT_COLLECTION="soc_attacks"
```

### 3. Seed RAG Database (Required)

As mentioned above, you must populate the RAG database before running the application:
```bash
# Quick test (6 examples):
python scripts/seed_rag.py

# OR full dataset (61,792 items - recommended):
python scripts/seed_rag_from_csic.py
```

Verify Qdrant:
```bash
python scripts/check_chromadb.py
```

### 4. Run API Server

```bash
python api.py
```
The API will be available at `http://127.0.0.1:8000`.

### 5. Test Endpoint

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      "/api/users?id=1 OR 1=1",
      "/search?q=<script>alert(1)</script>",
      "/api/data?filter=../../etc/passwd"
    ]
  }'
```

## Testing the Pipeline

Run the test suites to verify all components:

```bash
# Test cache-first flow (4 comprehensive tests)
python tests/test_cache_flow.py

# Test fast/slow path routing
python tests/demo_fast_slow_paths.py

# Test full end-to-end pipeline
python tests/test_full_pipeline.py

# Test RAG search functionality
python tests/test_rag_search.py

# Quick sanity check
python tests/sanity_check.py
```

## Development Tools

```bash
# Generate LangGraph visualization
python scripts/visualize_graph.py

# Check Qdrant contents
python scripts/inspect_chromadb.py

# Debug cache operations
python scripts/debug_cache.py
```

## Contributing

See [PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md) for complete project structure and [QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md) for development commands.

## License

MIT License
