import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from graph_app import soc_app
import pprint
# monkeypatch cache and rag to reproduce test environment
import backends.cache_backend as cb
import nodes.nodes_rag as n_rag
cb.cache_get = lambda txt: None
cb.cache_set = lambda txt,val: None
n_rag.vector_search = lambda q,k=3: []

print('Invoking batch...')
res = soc_app.invoke({'requests': ['GET /foo HTTP/1.1' for _ in range(3)]})
pprint.pprint(res)
