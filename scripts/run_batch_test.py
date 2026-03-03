import time
import sys
from pathlib import Path
# ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))
from graph_app import soc_app
# avoid RAG network dependency by monkey patching
from backends import rag_backend
rag_backend.vector_search = lambda query, k=3: []
# also override reference used by nodes
import nodes.nodes_rag as nodes_rag
nodes_rag.vector_search = lambda query, k=3: []

# first scenario: generic fast path (likely LLM because ping is neither obvious attack nor safe)
requests = ["GET /ping HTTP/1.1"] * 50
payload = {"requests": requests}
start = time.time()
result = soc_app.invoke(payload)
elapsed = time.time() - start
print(f"Scenario 1 (ping x50): {elapsed:.3f}s")

# second scenario: rule-engine will block (fast path, no LLM)
requests2 = ["GET /users?id=1 UNION SELECT password FROM users"] * 50
payload2 = {"requests": requests2}
start2 = time.time()
result2 = soc_app.invoke(payload2)
elapsed2 = time.time() - start2
print(f"Scenario 2 (SQLi x50): {elapsed2:.3f}s")
