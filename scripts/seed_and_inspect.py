#!/usr/bin/env python
"""Seed RAG and immediately inspect Qdrant contents in same process."""

import sys
from pathlib import Path

# Add workspace root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import add_rag_example, client, COLLECTION_NAME

print("\n" + "=" * 80)
print("SEEDING QDRANT")
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
print("QDRANT COLLECTION CONTENTS")
print("=" * 80 + "\n")

count = client.count(collection_name=COLLECTION_NAME, exact=True)
total_items = count.count

if total_items == 0:
    print("[ERROR] Collection is empty!")
    sys.exit(1)

print("Total items: {}\n".format(total_items))

normal_count = 0
anomalous_count = 0
attack_types = {}
emb_dim = "N/A"

next_offset = None
i = 1
while True:
    points, next_offset = client.scroll(
        collection_name=COLLECTION_NAME,
        limit=100,
        with_payload=True,
        with_vectors=True,
        offset=next_offset,
    )

    for point in points:
        payload = point.payload or {}
        label = payload.get("label", "N/A")
        attack_type = payload.get("attack_type", "N/A")
        doc_text = payload.get("raw_request", "")
        doc_id = str(point.id)

        print("Item #{}".format(i))
        print("  ID (SHA256): {}".format(doc_id))
        print("  Request Text: {}".format(doc_text))
        print("  Label: {}".format(label))
        print("  Attack Type: {}".format(attack_type))
        print()

        if label == "normal":
            normal_count += 1
        elif label == "anomalous":
            anomalous_count += 1

        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        if point.vector and emb_dim == "N/A":
            emb_dim = len(point.vector)

        i += 1

    if not next_offset:
        break

print("=" * 80)
print("SUMMARY STATISTICS")
print("=" * 80)
print("[OK] Total items stored: {}".format(total_items))
print("[OK] Normal requests: {}".format(normal_count))
print("[OK] Anomalous requests: {}".format(anomalous_count))
print("[OK] Embedding dimensions: {}".format(emb_dim))

# Attack type breakdown
print("\nAttack Type Breakdown:")
for attack_type, count in attack_types.items():
    print("  - {}: {}".format(attack_type or 'Normal', count))

print("\n[SUCCESS] Qdrant inspection complete!")
