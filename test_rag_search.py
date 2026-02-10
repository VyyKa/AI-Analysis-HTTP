"""Test RAG retrieval with a specific request"""
from backends.rag_backend import vector_search, collection
import json

# Check ChromaDB size first
items = collection.get()
print(f"ChromaDB total items: {len(items['ids'])}\n")

if len(items['ids']) == 0:
    print("⚠️  ChromaDB is empty - seed dataset first!")
    exit(1)

# Test request
test_request = """POST /tienda1/miembros/editar.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5
Accept-Language: en
Host: localhost:8080
Cookie: JSESSIONID=F8F9F13A97715B436014E7C27BD0BD7B
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 296
modo=registro&login=yigal&password=anF6_9ti4915&nombre=Sharim&apellidos=Grino+Crosas&email=santacroce_prueckner@puravidasa.bn&dni=68875056S&direccion=C/+Padre+Presentat,+26+&ciudadA=Torremanzanas/Torre+de+les+Maanes,+la&cp=31750&provincia=vila&ntc=7191364141648176&B1=Registrar"""

print("=" * 80)
print("TEST REQUEST:")
print("=" * 80)
print(test_request[:200] + "...")
print()

# Search for similar examples
print("=" * 80)
print("RAG SEARCH RESULTS (Top 5 similar):")
print("=" * 80)

results = vector_search(test_request, k=5)

for i, result in enumerate(results, 1):
    print(f"\n[{i}] Label: {result['label'].upper()} | Attack Type: {result['attack_type']}")
    print(f"    Request: {result['raw_request'][:150]}...")
    print()

# Summary
labels = [r['label'] for r in results]
print("=" * 80)
print("SUMMARY:")
print("=" * 80)
print(f"Normal: {labels.count('normal')}")
print(f"Anomalous: {labels.count('anomalous')}")
print()

# Attack type breakdown
attack_types = {}
for r in results:
    at = r['attack_type']
    attack_types[at] = attack_types.get(at, 0) + 1

print("Attack type breakdown:")
for attack_type, count in attack_types.items():
    print(f"  - {attack_type}: {count}")
