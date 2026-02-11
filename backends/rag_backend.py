import hashlib
import os
import uuid
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

model = SentenceTransformer("all-MiniLM-L6-v2")

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "soc_attacks")
VECTOR_SIZE = 384

client = QdrantClient(url=QDRANT_URL)


def _ensure_collection() -> None:
    if not client.collection_exists(collection_name=COLLECTION_NAME):
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=qmodels.VectorParams(
                size=VECTOR_SIZE,
                distance=qmodels.Distance.COSINE,
            ),
        )


def _make_doc_id(text: str) -> str:
    """Create stable checksum ID for document"""
    digest = hashlib.sha256(text.encode()).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, digest))


def add_rag_example(text: str, is_anomalous: bool, attack_type: str = None):
    """Add example to RAG collection.
    
    Args:
        text: Request/payload text
        is_anomalous: True if attack/anomalous, False if normal
        attack_type: Type of attack (e.g., 'SQL Injection', 'XSS'). Can be None for normal requests.
    """
    _ensure_collection()
    emb = model.encode(text).tolist()
    doc_id = _make_doc_id(text)
    payload = {
        "raw_request": text,
        "label": "anomalous" if is_anomalous else "normal",
        "attack_type": attack_type or "normal",
    }
    client.upsert(
        collection_name=COLLECTION_NAME,
        points=[
            qmodels.PointStruct(
                id=doc_id,
                vector=emb,
                payload=payload,
            )
        ],
    )

def vector_search(query: str, k: int = 3):
    _ensure_collection()
    emb = model.encode(query).tolist()
    hits = client.query_points(
        collection_name=COLLECTION_NAME,
        query=emb,
        limit=k,
        with_payload=True,
    ).points

    results = []
    for hit in hits:
        payload = hit.payload or {}
        results.append({
            "raw_request": payload.get("raw_request", ""),
            "label": payload.get("label", "normal"),
            "attack_type": payload.get("attack_type", "normal"),
        })
    return results

def rag_list_parser(results: list[dict]) -> str:
    """Format RAG results for LLM context."""
    if not results:
        return ""
    return "\n".join(
        f"[{r['label'].upper()}] {r['attack_type']}: {r['raw_request']}"
        for r in results
    )
