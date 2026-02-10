import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backends.rag_backend import add_rag_example

# Anomalous examples
add_rag_example("id=1 UNION SELECT password FROM users", is_anomalous=True, attack_type="SQL Injection")
add_rag_example("<script>alert(1)</script>", is_anomalous=True, attack_type="XSS")
add_rag_example("../../etc/passwd", is_anomalous=True, attack_type="Path Traversal")

# Normal examples
add_rag_example("/api/users", is_anomalous=False)
add_rag_example("/search?q=python", is_anomalous=False)
add_rag_example("/home", is_anomalous=False)
