import time
import statistics
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import vector_search

query = "id=1 UNION SELECT password FROM users"


def timed_search(q, k=3):
    t0 = time.perf_counter()
    vector_search(q, k=k)
    return time.perf_counter() - t0


def percentile(data, p):
    if not data:
        return 0.0
    k = int((len(data) - 1) * p)
    return data[k]


# warmup
vector_search(query, k=3)

total = 100
k = 3

print("QDRANT PER-REQUEST LATENCY")
print(f"total requests: {total}")
print(f"k: {k}")
print()

latencies_ms = []
start = time.perf_counter()
for i in range(1, total + 1):
    latency = timed_search(query, k=k) * 1000
    latencies_ms.append(latency)
    print(f"{i:03d}  {latency:.2f} ms")
end = time.perf_counter()

latencies_ms.sort()
print()
print(f"Total time: {(end - start):.2f} s")
print(f"Avg latency: {statistics.mean(latencies_ms):.2f} ms")
print(f"P95 latency: {percentile(latencies_ms, 0.95):.2f} ms")
print(f"P99 latency: {percentile(latencies_ms, 0.99):.2f} ms")
