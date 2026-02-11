"""Quick check ChromaDB size"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import collection

items = collection.get()
print(f"ChromaDB total items: {len(items['ids'])}")

if len(items['ids']) == 0:
    print("⚠️  ChromaDB is EMPTY - need to seed full dataset!")
else:
    print(f"✅ ChromaDB has {len(items['ids'])} items")
    # Show attack type breakdown
    attack_types = {}
    for m in items.get("metadatas", []):
        at = m.get("attack_type", "normal")
        attack_types[at] = attack_types.get(at, 0) + 1
    
    print("\nAttack type breakdown:")
    for attack_type, count in sorted(attack_types.items(), key=lambda x: -x[1])[:10]:
        print(f"  - {attack_type}: {count}")
