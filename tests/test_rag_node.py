"""Unit tests for the RAG node in the state graph."""
import sys
from pathlib import Path

# make sure workspace root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from nodes.nodes_rag import rag_node


def simple_state(request_text: str):
    return {"items": [{"id": "1", "raw_request": request_text}]}


if __name__ == "__main__":
    print("Testing rag_node behavior")
    st = simple_state("ping")
    out = rag_node(st)
    item = out["items"][0]
    print("rag_context:", repr(item.get("rag_context")))
    if item.get("rag_context") is None:
        print("⚠️  rag_context not set")
        sys.exit(1)
    else:
        print("✅ rag_context populated (may be empty string if collection empty)")
