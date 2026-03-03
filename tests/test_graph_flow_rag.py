"""Verify graph routing puts RAG only on slow path and not on fast/cache-hit path."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from graph_app import soc_app


def run_state(request_text):
    # execute graph via invoke()
    return soc_app.invoke({"requests": [request_text]})


def test_slow_path_includes_rag():
    # choose a request that will not be blocked by rule engine (e.g., low score)
    result = run_state("`whoami`")
    item = result["items"][0]
    assert item.get("fast_decision") == "REVIEW"
    assert "rag_context" in item, "RAG context should be added on slow path"


def test_fast_path_no_rag():
    # a clearly malicious request that triggers fast block
    result = run_state("SELECT * FROM users WHERE id=1' UNION SELECT *")
    item = result["items"][0]
    assert item.get("fast_decision") == "BLOCK"
    # rag_context may be absent or empty
    assert item.get("rag_context", "") == "", "Fast path should skip RAG"


if __name__ == "__main__":
    print("Running flow tests for RAG placement")
    test_slow_path_includes_rag()
    print("Slow path test passed")
    test_fast_path_no_rag()
    print("Fast path test passed")
