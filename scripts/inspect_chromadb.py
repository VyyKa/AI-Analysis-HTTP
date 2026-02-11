"""Inspect Qdrant collection contents"""

import sys
from pathlib import Path

# Add parent directory to path
script_dir = Path(__file__).parent
parent_dir = script_dir.parent
sys.path.insert(0, str(parent_dir))

import json
from backends.rag_backend import client, COLLECTION_NAME

def inspect_chromadb():
    """Display all stored items in Qdrant"""
    
    print("=" * 80)
    print("QDRANT COLLECTION INSPECTION")
    print("=" * 80)
    
    # Get all items from collection
    try:
        count = client.count(collection_name=COLLECTION_NAME, exact=True)
        total_items = count.count

        if total_items == 0:
            print("\n❌ Collection is empty. Seed with: python scripts/seed_rag.py")
            return

        print(f"\n✅ Total items in collection: {total_items}\n")

        normal_count = 0
        anomalous_count = 0
        attack_types = {}

        # Scroll through all points
        next_offset = None
        idx = 1
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
                vector = point.vector or []
                doc_id = str(point.id)

                print(f"Item #{idx}")
                print(f"  ID:        {doc_id[:32]}..." if len(doc_id) > 32 else f"  ID:        {doc_id}")
                print(f"  Request:   {payload.get('raw_request', '')}")
                print(f"  Label:     {payload.get('label', 'N/A')}")
                print(f"  Type:      {payload.get('attack_type', 'N/A')}")

                label = payload.get("label")
                if label == "normal":
                    normal_count += 1
                elif label == "anomalous":
                    anomalous_count += 1

                attack_type = payload.get("attack_type", "unknown")
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

                if vector:
                    print(f"  Embedding: {len(vector)} dimensions, sample: [{vector[0]:.4f}, {vector[1]:.4f}, ...]")
                print()
                idx += 1

            if not next_offset:
                break
        
        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        print(f"Total items:      {total_items}")
        print(f"Normal requests:  {normal_count}")
        print(f"Anomalous:        {anomalous_count}")

        print("\nAttack types:")
        for attack_type, count in sorted(attack_types.items()):
            print(f"  - {attack_type}: {count}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    inspect_chromadb()
