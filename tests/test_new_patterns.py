"""Test all new attack type patterns"""
from rule_engine import analyze_request
import json

tests = {
    'Open Redirect': 'POST /auth/?url=//attacker.site HTTP/1.1',
    'SSTI Jinja': 'GET /template {{ 7*7 }} HTTP/1.1',
    'SSTI PHP': '<?php echo eval($_GET["code"]); ?>',
    'XXE': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    'CRLF Injection': 'POST /search\r\nSet-Cookie: admin=1',
    'NoSQL Injection': 'POST /mongo?{"$where":"1==1"}',
    'LDAP Injection': 'POST /ldap with cn=*,|(cn=*)',
    'HTML Injection': 'GET /<meta charset=utf-8>',
    'CSRF Token': 'csrf=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
    'Web Cache': 'Cache-Control: no-store\r\nX-Original-URL: /admin',
}

print("=" * 80)
print("NEW ATTACK TYPE PATTERNS TEST")
print("=" * 80)

for name, payload in tests.items():
    result = analyze_request(payload)
    attack_type = result.get("attack_type", "Unknown")
    score = result.get("rule_score", 0)
    decision = result.get("fast_decision", "N/A")
    
    print(f"\n{name}:")
    print(f"  Type: {attack_type}")
    print(f"  Score: {score}")
    print(f"  Decision: {decision}")
    if result.get("attack_candidates"):
        for candidate in result["attack_candidates"][:1]:
            print(f"  Rules: {candidate['rule_matches']}")

print("\n" + "=" * 80)
print("Full sample outputs (first 2):")
print("=" * 80)

for i, (name, payload) in enumerate(list(tests.items())[:2]):
    result = analyze_request(payload)
    print(f"\n{name}:")
    print(json.dumps(result, indent=2, default=str))
