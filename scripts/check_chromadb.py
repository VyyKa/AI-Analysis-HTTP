"""Quick check Qdrant collection size"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import client, COLLECTION_NAME

count = client.count(collection_name=COLLECTION_NAME, exact=True)
total = count.count
print(f"Qdrant total items: {total}")

if total == 0:
    print("⚠️  Qdrant collection is EMPTY - need to seed full dataset!")
else:
    print(f"✅ Qdrant has {total} items")
