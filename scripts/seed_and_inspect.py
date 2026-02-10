#!/usr/bin/env python
"""Seed RAG and immediately inspect ChromaDB contents in same process."""

import sys
from pathlib import Path

# Add workspace root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import add_rag_example, collection

print("\n" + "=" * 80)
print("SEEDING CHROMADB")
print("=" * 80)

# Seed data
examples = [
    ("id=1 UNION SELECT password FROM users", True, "SQL Injection"),
    ("<script>alert(1)</script>", True, "XSS"),
    ("../../etc/passwd", True, "Path Traversal"),
    ("/api/users", False, None),
    ("/search?q=hello", False, None),
]

for text, is_anomalous, attack_type in examples:
    add_rag_example(text, is_anomalous=is_anomalous, attack_type=attack_type)
    label_val = 'anomalous' if is_anomalous else 'normal'
    type_val = attack_type or 'N/A'
    print("[OK] Added: {}... | Label: {} | Type: {}".format(text[:50], label_val, type_val))

# Immediately inspect in same process
print("\n" + "=" * 80)
print("CHROMADB COLLECTION CONTENTS")
print("=" * 80 + "\n")

items = collection.get()

if not items["ids"]:
    print("[ERROR] Collection is empty!")
    sys.exit(1)

print("Total items: {}\n".format(len(items['ids'])))

for i, (doc_id, doc_text, metadata) in enumerate(
    zip(items["ids"], items["documents"], items.get("metadatas", [])), 1
):
    label = metadata.get("label", "N/A")
    attack_type = metadata.get("attack_type", "N/A")
    
    print("Item #{}".format(i))
    print("  ID (SHA256): {}".format(doc_id))
    print("  Request Text: {}".format(doc_text))
    print("  Label: {}".format(label))
    print("  Attack Type: {}".format(attack_type))
    print()

# Summary stats
labels = [m.get("label") for m in items.get("metadatas", [])]
normal_count = labels.count("normal")
anomalous_count = labels.count("anomalous")

print("=" * 80)
print("SUMMARY STATISTICS")
print("=" * 80)
print("[OK] Total items stored: {}".format(len(items['ids'])))
print("[OK] Normal requests: {}".format(normal_count))
print("[OK] Anomalous requests: {}".format(anomalous_count))
emb_dim = len(items['embeddings'][0]) if items.get('embeddings') else 'N/A'
print("[OK] Embedding dimensions: {}".format(emb_dim))

# Attack type breakdown
attack_types = {}
for m in items.get("metadatas", []):
    at = m.get("attack_type", "normal")
    attack_types[at] = attack_types.get(at, 0) + 1

print("\nAttack Type Breakdown:")
for attack_type, count in attack_types.items():
    print("  - {}: {}".format(attack_type or 'Normal', count))

print("\n[SUCCESS] ChromaDB inspection complete!")
