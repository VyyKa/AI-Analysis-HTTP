"""Append-only backend for detailed analysis logs."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ANALYSIS_LOG_FILE = Path(__file__).parent.parent / "data" / "analysis_logs.jsonl"


def _ensure_log_dir() -> None:
    ANALYSIS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def append_analysis_log(cache_key: str, analysis_payload: Dict[str, Any]) -> None:
    """Append one analysis record to JSONL logs."""
    _ensure_log_dir()
    record = {
        "cache_key": cache_key,
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "analysis": analysis_payload,
    }
    try:
        with open(ANALYSIS_LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=True) + "\n")
    except Exception as exc:
        print(f"Warning: Failed to append analysis log: {exc}")


def get_analysis_logs(limit: int = 50, cache_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read latest analysis logs, optionally filtering by cache key."""
    if limit <= 0 or not ANALYSIS_LOG_FILE.exists():
        return []

    try:
        lines = ANALYSIS_LOG_FILE.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []

    results: List[Dict[str, Any]] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if cache_key and record.get("cache_key") != cache_key:
            continue

        results.append(record)
        if len(results) >= limit:
            break

    return results


def get_latest_analysis_log(cache_key: str) -> Optional[Dict[str, Any]]:
    """Get the most recent analysis log by cache key."""
    logs = get_analysis_logs(limit=1, cache_key=cache_key)
    return logs[0] if logs else None
