#!/usr/bin/env python3
from rule_engine import analyze_request

tests = [
    ('Safe: hello', 'hello world', 'ALLOW', 0),
    ('Unknown: quote', "id='", 'REVIEW', 0),
    ('Attack: SQLi', 'id=1 OR 1=1 UNION SELECT', 'BLOCK', 5),
    ('Attack: XSS', '<script>alert(1)</script>', 'BLOCK', 5),
]

print('SANITY CHECK - All Critical Cases')
print('=' * 70)
all_good = True
for name, payload, exp_decision, min_score in tests:
    result = analyze_request(payload)
    score = result.get('inbound_anomaly_score', 0)
    decision = result.get('fast_decision') or 'NULL'
    
    ok = (decision == exp_decision) and (score >= min_score)
    status = 'OK' if ok else 'ERROR'
    all_good = all_good and ok
    
    print(f'{status} | {name:<20} Score: {score:>3} Decision: {decision}')

print('=' * 70)
result_msg = 'ALL OK - ZERO ERRORS' if all_good else 'SOME FAILED'
print(f'Result: {result_msg}')
