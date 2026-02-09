import json
from datetime import datetime

def audit_log(item: dict):
    record = {
        "time": datetime.utcnow().isoformat(),
        **item
    }

    with open("soc_audit.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
