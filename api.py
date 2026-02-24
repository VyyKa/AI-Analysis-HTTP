from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from graph_app import soc_app
from backends.cache_backend import _CACHE, _make_key, _save_cache

WEB_UI_DIR = Path(__file__).parent / "web_ui"

app = FastAPI(title="SOC LangGraph API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Web UI ──────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    index = WEB_UI_DIR / "index.html"
    return FileResponse(index)


# ── Core ────────────────────────────────────────────

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "soc-analysis"}


@app.post("/analyze")
def analyze(payload: dict):
    """
    Analyze HTTP requests for security threats.

    Request body:
    {
      "requests": [
        "hello world",
        "id=1 UNION SELECT password FROM users"
      ]
    }
    """
    return soc_app.invoke(payload)


# ── Cache endpoints (for Web UI) ───────────────────

@app.get("/cache/history")
def cache_history(limit: int = Query(default=50, ge=1, le=500)):
    """Return cached analysis entries for the history view."""
    items = []
    for key, value in list(_CACHE.items())[:limit]:
        entry = {
            "cache_key": key,
            "raw_request": value.get("raw_request", ""),
            "attack_type": value.get("attack_type", "Unknown"),
            "severity": value.get("severity", "Info"),
            "rule_score": value.get("rule_score", 0),
            "fast_decision": value.get("fast_decision", "?"),
            "blocked": value.get("blocked", False),
            "cache_written_at": value.get("cache_written_at", None),
        }
        items.append(entry)
    return {"items": items, "total": len(_CACHE)}


@app.delete("/cache/{cache_key}")
def delete_cache_entry(cache_key: str):
    """Delete a single cache entry by key."""
    if cache_key in _CACHE:
        del _CACHE[cache_key]
        _save_cache()
        return {"status": "deleted", "cache_key": cache_key}
    return {"status": "not_found", "cache_key": cache_key}


@app.delete("/cache")
def clear_all_cache():
    """Clear all cache entries (memory + disk)."""
    count = len(_CACHE)
    _CACHE.clear()
    _save_cache()
    return {"status": "cleared", "deleted_count": count}
