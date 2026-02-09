import chromadb
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")

client = chromadb.Client()
collection = client.get_or_create_collection("soc_attacks")

def add_rag_example(text: str, label: str):
    emb = model.encode(text).tolist()
    collection.add(
        documents=[text],
        metadatas=[{"label": label}],
        embeddings=[emb],
        ids=[text[:32]]
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
            "label": meta["label"]
        })
    return results

def rag_list_parser(results: list[dict]) -> str:
    if not results:
        return ""
    return "\n".join(
        f"{r['label']}: {r['raw_request']}"
        for r in results
    )
