import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import add_rag_example

# Advanced Anomalous examples
add_rag_example("id=1 UNION SELECT password FROM users", is_anomalous=True, attack_type="SQL Injection")
add_rag_example("<script>alert(1)</script>", is_anomalous=True, attack_type="XSS")
add_rag_example("../../etc/passwd", is_anomalous=True, attack_type="Path Traversal")
add_rag_example("${7*7}", is_anomalous=True, attack_type="Server-Side Template Injection")
add_rag_example('{"user": {"$ne": null}, "password": {"$ne": null}}', is_anomalous=True, attack_type="NoSQL Injection")
add_rag_example("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", is_anomalous=True, attack_type="XSS (Base64)") # <script>alert(1)</script>
add_rag_example("admin' --", is_anomalous=True, attack_type="SQL Injection")
add_rag_example("1; DROP TABLE users", is_anomalous=True, attack_type="SQL Injection")
add_rag_example("<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", is_anomalous=True, attack_type="XML External Entity")
add_rag_example("() { :;}; /bin/bash -c 'echo vulnerable'", is_anomalous=True, attack_type="Command Injection (Shellshock)")


# Normal examples
add_rag_example("/api/users", is_anomalous=False)
add_rag_example("/search?q=python", is_anomalous=False)
add_rag_example("/home", is_anomalous=False)
add_rag_example('{"username": "john_doe", "email": "john@example.com"}', is_anomalous=False)
add_rag_example("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI...", is_anomalous=False)
