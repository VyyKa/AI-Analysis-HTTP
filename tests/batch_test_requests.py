import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/../'))
from backends.rule_engine import analyze_request

REQUESTS_FILE = os.path.join(os.path.dirname(__file__), 'test_requests.txt')


def parse_multiline_requests(filename):
    requests = []
    with open(filename, encoding='utf-8') as f:
        in_block = False
        current = []
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('"') and not in_block:
                in_block = True
                current = [line[1:]]
            elif line.endswith('"') and in_block:
                current.append(line[:-1])
                requests.append('\n'.join(current).strip())
                in_block = False
                current = []
            elif in_block:
                current.append(line)
    return requests

def main():
    requests = parse_multiline_requests(REQUESTS_FILE)
    print(f"Testing {len(requests)} requests...\n")
    results = []
    for idx, req in enumerate(requests, 1):
        try:
            res = analyze_request(req)
            results.append({
                'input': req,
                'decision': res.get('fast_decision', ''),
                'attack_type': res.get('attack_type', ''),
                'severity': res.get('severity', ''),
                'score': res.get('inbound_anomaly_score', ''),
                'path': 'FAST' if res.get('fast_decision', '').upper() in ['BLOCK', 'ALLOW'] and res.get('llm_model') is None else 'SLOW',
                'llm_model': res.get('llm_model', None)
            })
            print(f"{idx:3d}. {req.splitlines()[0][:40]:<40} | {results[-1]['decision']:<8} | {results[-1]['path']:<4} | {results[-1]['attack_type']:<18} | {results[-1]['severity']:<8} | {results[-1]['score']}")
        except Exception as e:
            print(f"{idx:3d}. {req.splitlines()[0][:40]:<40} | ERROR: {e}")
    # Optionally, write results to a file
    with open('test_results_summary.txt', 'w', encoding='utf-8') as out:
        for r in results:
            out.write(f"{r['input']} | {r['decision']} | {r['path']} | {r['attack_type']} | {r['severity']} | {r['score']} | {r['llm_model']}\n")
    print("\nSummary written to test_results_summary.txt")

if __name__ == "__main__":
    main()
