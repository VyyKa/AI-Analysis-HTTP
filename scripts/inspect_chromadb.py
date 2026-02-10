"""Inspect ChromaDB collection contents"""

import sys
from pathlib import Path

# Add parent directory to path
script_dir = Path(__file__).parent
parent_dir = script_dir.parent
sys.path.insert(0, str(parent_dir))

import json
from backends.rag_backend import collection

def inspect_chromadb():
    """Display all stored items in ChromaDB"""
    
    print("=" * 80)
    print("CHROMADB COLLECTION INSPECTION")
    print("=" * 80)
    
    # Get all items from collection
    try:
        # Query with very high number to get all items
        all_items = collection.get()
        
        if not all_items or not all_items['ids']:
            print("\n❌ Collection is empty. Seed with: python scripts/seed_rag.py")
            return
        
        total_items = len(all_items['ids'])
        print(f"\n✅ Total items in collection: {total_items}\n")
        
        # Display each item
        for idx, (doc_id, document, metadata, embedding) in enumerate(
            zip(
                all_items['ids'],
                all_items['documents'],
                all_items.get('metadatas', [{}] * len(all_items['ids'])),
                all_items.get('embeddings', [None] * len(all_items['ids']))
            ),
            1
        ):
            print(f"Item #{idx}")
            print(f"  ID:        {doc_id[:32]}..." if len(doc_id) > 32 else f"  ID:        {doc_id}")
            print(f"  Request:   {document}")
            print(f"  Label:     {metadata.get('label', 'N/A')}")
            print(f"  Type:      {metadata.get('attack_type', 'N/A')}")
            
            if embedding:
                print(f"  Embedding: {len(embedding)} dimensions, sample: [{embedding[0]:.4f}, {embedding[1]:.4f}, ...]")
            print()
        
        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        normal_count = sum(1 for m in all_items.get('metadatas', []) if m.get('label') == 'normal')
        anomalous_count = sum(1 for m in all_items.get('metadatas', []) if m.get('label') == 'anomalous')
        
        print(f"Total items:      {total_items}")
        print(f"Normal requests:  {normal_count}")
        print(f"Anomalous:        {anomalous_count}")
        
        attack_types = {}
        for m in all_items.get('metadatas', []):
            attack_type = m.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        print(f"\nAttack types:")
        for attack_type, count in sorted(attack_types.items()):
            print(f"  - {attack_type}: {count}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    inspect_chromadb()
