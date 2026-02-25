import requests
import os
import time

API_URL = "http://localhost:8000/analyze"
REQUESTS_FILE = os.path.join(os.path.dirname(__file__), 'test_requests.txt')


def parse_multiline_requests(filename):
    requests_list = []
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
                requests_list.append('\n'.join(current).strip())
                in_block = False
                current = []
            elif in_block:
                current.append(line)
    return requests_list

def main():
    requests_list = parse_multiline_requests(REQUESTS_FILE)
    print(f"Sending {len(requests_list)} requests to API...\n")
    results = []
    for idx, req in enumerate(requests_list, 1):
        try:
            resp = requests.post(API_URL, json={"requests": [req]})
            data = resp.json()
            result = data.get('results', [{}])[0]
            results.append({
                'input': req,
                'decision': result.get('decision', ''),
                'attack_type': result.get('attack_type', ''),
                'severity': result.get('severity', ''),
                'score': result.get('rule_score', ''),
                'llm_model': result.get('llm_model', None),
                'cache_hit': result.get('cache_hit', False)
            })
            print(f"{idx:3d}. {req.splitlines()[0][:40]:<40} | {results[-1]['decision']:<8} | {results[-1]['attack_type']:<18} | {results[-1]['severity']:<8} | {results[-1]['score']:<3} | LLM: {results[-1]['llm_model'] or '-'} | Cache: {results[-1]['cache_hit']}")
        except Exception as e:
            print(f"{idx:3d}. {req.splitlines()[0][:40]:<40} | ERROR: {e}")
        time.sleep(0.05)  # avoid flooding API
    with open('test_api_results_summary.txt', 'w', encoding='utf-8') as out:
        for r in results:
            out.write(f"{r['input']} | {r['decision']} | {r['attack_type']} | {r['severity']} | {r['score']} | {r['llm_model']} | {r['cache_hit']}\n")
    print("\nSummary written to test_api_results_summary.txt")

if __name__ == "__main__":
    main()
