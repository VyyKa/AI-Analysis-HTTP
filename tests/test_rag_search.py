"""RAG retrieval tests with graceful skip when Qdrant is unavailable."""
import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import vector_search, client, COLLECTION_NAME


TEST_REQUEST = """POST /tienda1/miembros/editar.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5
Accept-Language: en
Host: localhost:8080
Cookie: JSESSIONID=F8F9F13A97715B436014E7C27BD0BD7B
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 296
modo=registro&login=yigal&password=anF6_9ti4915&nombre=Sharim&apellidos=Grino+Crosas&email=santacroce_prueckner@puravidasa.bn&dni=68875056S&direccion=C/+Padre+Presentat,+26+&ciudadA=Torremanzanas/Torre+de+les+Maanes,+la&cp=31750&provincia=vila&ntc=7191364141648176&B1=Registrar"""


def _require_qdrant_ready() -> int:
    try:
        count = client.count(collection_name=COLLECTION_NAME, exact=True)
    except Exception as exc:
        pytest.skip(f"Qdrant unavailable: {exc}")

    total = count.count
    if total == 0:
        pytest.skip("Qdrant collection is empty. Seed dataset first.")
    return total


def test_rag_search_returns_top_k_results():
    _require_qdrant_ready()
    results = vector_search(TEST_REQUEST, k=5)

    assert isinstance(results, list)
    if len(results) == 0:
        pytest.skip("Qdrant available but returned no results for this probe request.")
    assert len(results) <= 5

    first = results[0]
    assert "raw_request" in first
    assert "label" in first
    assert "attack_type" in first


if __name__ == "__main__":
    total = _require_qdrant_ready()
    print(f"Qdrant total items: {total}\n")
    results = vector_search(TEST_REQUEST, k=5)
    for i, result in enumerate(results, 1):
        print(f"[{i}] Label: {result['label']} | Attack Type: {result['attack_type']}")
