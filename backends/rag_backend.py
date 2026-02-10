import chromadb
import hashlib
from sentence_transformers import SentenceTransformer
from pathlib import Path

model = SentenceTransformer("all-MiniLM-L6-v2")

# Use persistent storage instead of in-memory
chroma_path = Path(__file__).parent.parent / "chroma_db"
client = chromadb.PersistentClient(path=str(chroma_path))
collection = client.get_or_create_collection("soc_attacks")


def _make_doc_id(text: str) -> str:
    """Create stable checksum ID for document"""
    return hashlib.sha256(text.encode()).hexdigest()


def add_rag_example(text: str, is_anomalous: bool, attack_type: str = None):
    """Add example to RAG collection.
    
    Args:
        text: Request/payload text
        is_anomalous: True if attack/anomalous, False if normal
        attack_type: Type of attack (e.g., 'SQL Injection', 'XSS'). Can be None for normal requests.
    """
    emb = model.encode(text).tolist()
    doc_id = _make_doc_id(text)
    collection.add(
        documents=[text],
        metadatas=[{
            "label": "anomalous" if is_anomalous else "normal",
            "attack_type": attack_type or "normal"
        }],
        embeddings=[emb],
        ids=[doc_id]
    )

def vector_search(query: str, k: int = 3):
    emb = model.encode(query).tolist()
    res = collection.query(
        query_embeddings=[emb],
        n_results=k
    )

    results = []
    for doc, meta in zip(res["documents"][0], res["metadatas"][0]):
        results.append({
            "raw_request": doc,
            "label": meta.get("label", "normal"),
            "attack_type": meta.get("attack_type", "normal")
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
