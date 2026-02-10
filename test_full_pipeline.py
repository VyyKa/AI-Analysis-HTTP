"""Test full pipeline with real request"""
import json
from graph_app import soc_app

# Test request từ user
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
print("FULL PIPELINE TEST")
print("=" * 80)
print(f"\nRequest: {test_request[:150]}...\n")

# Run through graph
print("Running through LangGraph pipeline...")
result = soc_app.invoke({
    "requests": [test_request]
})

print("\n" + "=" * 80)
print("PIPELINE RESULT")
print("=" * 80)

# Show route taken
if result.get("items"):
    item = result["items"][0]
    print(f"\n📍 Route taken: {item.get('route', 'unknown')}")
    print(f"   Cache hit: {item.get('cache_hit', False)}")
    print(f"   Blocked: {item.get('blocked', False)}")
    
    if item.get("attack_type"):
        print(f"\n🔍 Analysis:")
        print(f"   Attack type: {item.get('attack_type')}")
        print(f"   Rule score: {item.get('rule_score', 0)}")
        print(f"   Severity: {item.get('severity', 'N/A')}")

# Show final response
if result.get("result_json"):
    print("\n" + "=" * 80)
    print("FINAL RESPONSE")
    print("=" * 80)
    print(json.dumps(result["result_json"], indent=2, ensure_ascii=False))
else:
    print("\n⚠️  No result_json in output")
    print("Full state keys:", list(result.keys()))
