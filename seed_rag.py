from rag_backend import add_rag_example

add_rag_example("id=1 UNION SELECT password FROM users", "SQL Injection")
add_rag_example("<script>alert(1)</script>", "XSS")
add_rag_example("../../etc/passwd", "Path Traversal")
