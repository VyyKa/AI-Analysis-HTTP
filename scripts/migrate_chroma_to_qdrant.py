"""Migrate existing ChromaDB data into Qdrant."""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import chromadb
import uuid
from qdrant_client.http import models as qmodels
from backends.rag_backend import client, COLLECTION_NAME, VECTOR_SIZE


def migrate_chroma_to_qdrant() -> None:
    chroma_path = Path(__file__).parent.parent / "chroma_db"
    chroma_client = chromadb.PersistentClient(path=str(chroma_path))
    collection = chroma_client.get_or_create_collection("soc_attacks")

    all_items = collection.get(include=["embeddings", "metadatas", "documents"])
    ids = all_items.get("ids", [])
    docs = all_items.get("documents", [])
    metas = all_items.get("metadatas", [])
    embeddings = all_items.get("embeddings", [])

    if not ids:
        print("No items found in ChromaDB. Nothing to migrate.")
        return

    # Ensure collection exists in Qdrant
    if not client.collection_exists(collection_name=COLLECTION_NAME):
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=qmodels.VectorParams(
                size=VECTOR_SIZE,
                distance=qmodels.Distance.COSINE,
            ),
        )

    batch_size = 256
    total = len(ids)
    print(f"Migrating {total} items from ChromaDB to Qdrant...")

    for start in range(0, total, batch_size):
        end = min(start + batch_size, total)
        points = []
        for doc_id, doc_text, meta, emb in zip(
            ids[start:end],
            docs[start:end],
            metas[start:end],
            embeddings[start:end],
        ):
            payload = {
                "raw_request": doc_text,
                "label": meta.get("label", "normal") if isinstance(meta, dict) else "normal",
                "attack_type": meta.get("attack_type", "normal") if isinstance(meta, dict) else "normal",
            }
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(doc_id)))
            points.append(
                qmodels.PointStruct(
                    id=point_id,
                    vector=emb,
                    payload=payload,
                )
            )

        client.upsert(collection_name=COLLECTION_NAME, points=points)
        print(f"  Migrated {end}/{total}...")

    print("✅ Migration complete.")


if __name__ == "__main__":
    migrate_chroma_to_qdrant()
