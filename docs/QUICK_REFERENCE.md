# Quick Reference - Common Commands

## 🚀 Daily Workflow

### Start Working
```bash
cd "e:\DO AN MOI NHAT\LangChain"
venv_langgraph\Scripts\activate
```

### Check System Status
```bash
# Verify RAG database
python check_chromadb.py

# Check cache contents
python debug_cache.py

# Inspect ChromaDB details
python scripts/inspect_chromadb.py
```

### Run Tests
```bash
# Quick cache test
python test_cache_simple.py

# Full cache flow (4 tests)
python test_cache_flow.py

# Full pipeline test
python test_full_pipeline.py

# RAG search test
python test_rag_search.py

# Mock LLM test (no API key)
python tests/test_cache_mock.py
```

### Start API Server
```bash
python api.py
# Runs on http://127.0.0.1:8000
```

### Test API
```bash
# Simple test
curl -X POST http://127.0.0.1:8000/analyze -H "Content-Type: application/json" -d "{\"requests\": [\"SELECT * FROM users\"]}"

# Multiple requests
curl -X POST http://127.0.0.1:8000/analyze -H "Content-Type: application/json" -d "{\"requests\": [\"SELECT * FROM users\", \"GET /api/data\", \"<script>alert(1)</script>\"]}"
```

---

## 📦 Setup Commands (One-Time)

### Setup RAG Database
```bash
# Option 1: Quick test (6 examples, instant)
python scripts/seed_rag.py

# Option 2: Production (61k examples, 2-5 min)
python scripts/seed_rag_from_csic.py

# Verify seeding
python scripts/seed_and_inspect.py
```

### Generate Artifacts
```bash
# Generate graph diagrams
python scripts/visualize_graph.py

# Or use simple version
python scripts/visualize_graph_simple.py
```

---

## 🔍 Inspection Commands

### View RAG Contents
```bash
python scripts/inspect_chromadb.py
```

### Check Cache
```bash
python debug_cache.py
```

### Verify ChromaDB
```bash
python check_chromadb.py
```

---

## 🧪 Testing Commands

### All Tests
```bash
# Cache behavior tests
python test_cache_flow.py        # 4 tests with real API
python test_cache_simple.py      # Quick cache test
python tests/test_cache_mock.py  # Mock LLM

# Full pipeline
python test_full_pipeline.py

# RAG functionality
python test_rag_search.py

# Pattern detection
python tests/test_new_patterns.py

# Fast/slow path demo
python tests/demo_fast_slow_paths.py
```

---

## 🛠️ Development Commands

### Clear Cache
```bash
rm cache_data.pkl
```

### Clear ChromaDB
```bash
rm -rf chroma_db/
# Then reseed: python scripts/seed_rag.py
```

### Check Git Status
```bash
git status
git diff
```

### Commit Changes
```bash
git add .
git commit -m "feat: your message"
git push origin main
```

---

## 📊 Monitoring Commands

### Check System Resources
```bash
# Check Python process memory
Get-Process python | Select-Object WS, PM, CPU

# Check file sizes
Get-ChildItem -Recurse | Measure-Object -Property Length -Sum
```

### Check API Logs
```bash
# (API runs in foreground, logs to stdout)
python api.py | tee api.log
```

---

## 🔧 Configuration Commands

### View Environment
```bash
cat .env
```

### Update API Key
```bash
# Edit .env
notepad .env
# Or
echo "GROQ_API_KEY=your_new_key" > .env
```

### Check Python Version
```bash
python --version
# Should be: Python 3.11 or 3.12
```

---

## 📁 File Operations

### List Project Structure
```bash
tree /F  # Windows
ls -R    # Linux/Mac
```

### Find Files
```bash
# Find all Python files
Get-ChildItem -Recurse -Filter *.py

# Find specific file
Get-ChildItem -Recurse -Filter *cache*.py
```

### Search Code
```bash
# Search for text in files
Select-String -Path *.py -Pattern "def cache"
```

---

## 🐛 Debug Commands

### Run with Debug Output
```bash
# Python debug mode
python -m pdb test_cache_simple.py

# Verbose output
python api.py --log-level debug
```

### Check Imports
```bash
python -c "from backends.rag_backend import collection; print(collection.count())"
```

### Test Individual Functions
```bash
# Test rule engine
python -c "from backends.rule_engine import analyze_request; print(analyze_request('SELECT * FROM users'))"

# Test cache
python -c "from backends.cache_backend import cache_info; print(cache_info())"

# Test RAG
python -c "from backends.rag_backend import vector_search; print(vector_search('SELECT * FROM users'))"
```

---

## 📈 Performance Testing

### Benchmark Cache
```bash
# Run multiple times to see cache improvement
python test_cache_simple.py
python test_cache_simple.py  # Should be faster
```

### Time Commands
```bash
Measure-Command { python test_cache_simple.py }
```

---

## 🔄 Update Commands

### Update Dependencies
```bash
pip list --outdated
pip install --upgrade package_name
```

### Regenerate Requirements
```bash
pip freeze > requirements.txt
```

---

## 📚 Documentation Commands

### View Documentation
```bash
# Main overview
cat PROJECT_OVERVIEW.md

# Cache architecture
cat CACHE_FIRST_ARCHITECTURE.md

# Complete summary
cat docs/FINAL_PROJECT_SUMMARY.txt
```

### Generate New Docs
```bash
# Update this file when needed
notepad QUICK_REFERENCE.md
```

---

## 🎯 Common Workflows

### Workflow 1: Test New Feature
```bash
1. venv_langgraph\Scripts\activate
2. # Make code changes
3. python test_cache_simple.py
4. python test_full_pipeline.py
5. git add .
6. git commit -m "feat: new feature"
7. git push
```

### Workflow 2: Debug Issue
```bash
1. python check_chromadb.py  # Verify RAG
2. python debug_cache.py     # Check cache
3. # Identify issue
4. # Fix code
5. python test_cache_flow.py # Verify fix
```

### Workflow 3: Fresh Start
```bash
1. rm cache_data.pkl
2. rm -rf chroma_db/
3. python scripts/seed_rag.py
4. python check_chromadb.py
5. python test_cache_simple.py
```

---

## 💡 Tips & Tricks

### Faster Testing
```bash
# Use mock LLM to avoid API calls
python tests/test_cache_mock.py
```

### Quick Cache Check
```bash
# One-liner cache info
python -c "from backends.cache_backend import cache_info; print(cache_info())"
```

### Quick RAG Check
```bash
# One-liner RAG count
python -c "from backends.rag_backend import collection; print(f'Items: {collection.count()}')"
```

### Clear All Data
```bash
rm cache_data.pkl
rm -rf chroma_db/
rm -rf __pycache__/
rm -rf */__pycache__/
```

---

## ⚠️ Troubleshooting

### Issue: Module not found
```bash
# Ensure working directory is project root
cd "e:\DO AN MOI NHAT\LangChain"
```

### Issue: API key error
```bash
# Check .env
cat .env
# Should have: GROQ_API_KEY=gsk_...
```

### Issue: Empty ChromaDB
```bash
# Reseed database
python scripts/seed_rag.py
```

### Issue: Old cache data
```bash
# Clear and restart
rm cache_data.pkl
python test_cache_simple.py
```

---

**Last Updated:** February 11, 2026
