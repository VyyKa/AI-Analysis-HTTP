"""Debug cache operations"""
import hashlib
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.cache_backend import cache_info, cache_get

# Check cache after test
print("Cache info:", cache_info())

# Test hash matching
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

# Try to get from cache
cached = cache_get(test_request)
print(f"\nCache lookup result: {cached}")

if cached:
    print(f"Attack type: {cached.get('attack_type')}")
else:
    print("Not in cache")

# Show the hash that would be used
key_hash = hashlib.sha256(test_request.lower().encode()).hexdigest()
print(f"\nExpected cache key (SHA256): {key_hash[:16]}...")
