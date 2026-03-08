import hashlib
import pickle
from typing import Dict, Any, Optional, cast
from pathlib import Path

# Persistent cache file (moved to data/ folder)
CACHE_FILE = Path(__file__).parent.parent / "data" / "cache_data.pkl"

_CACHE: Dict[str, Any] = {}

def _save_cache():
    """Save cache to disk"""
    try:
        with open(CACHE_FILE, "wb") as f:
            pickle.dump(_CACHE, f)
    except Exception as e:
        print(f"Warning: Failed to save cache: {e}")


def _make_key(text: str) -> str:
    return hashlib.sha256(text.lower().encode()).hexdigest()


def _migrate_loaded_cache() -> bool:
    """Scrub legacy heavy/raw fields and normalize checksum metadata."""
    changed = False
    for key, value in _CACHE.items():
        if not isinstance(value, dict):
            continue

        if "raw_request" in value:
            value.pop("raw_request", None)
            changed = True

        if "full_output" in value:
            value.pop("full_output", None)
            changed = True

        if value.get("request_checksum") != key:
            value["request_checksum"] = key
            changed = True

        if value.get("cache_key") != key:
            value["cache_key"] = key
            changed = True

    return changed


# Load cache from disk on import
if CACHE_FILE.exists():
    try:
        with open(CACHE_FILE, "rb") as f:
            data = pickle.load(f)
            if isinstance(data, dict):
                _CACHE = cast(Dict[str, Any], data)
    except Exception:
        pass

if _CACHE and _migrate_loaded_cache():
    _save_cache()


def cache_get(text: str) -> Optional[Dict[str, Any]]:
    """Get full result object from cache"""
    key = _make_key(text)
    return _CACHE.get(key)


def cache_set(text: str, value: Dict[str, Any]) -> None:
    """Save full result object to cache"""
    key = _make_key(text)
    _CACHE[key] = value
    _save_cache()  # Save to disk after every write


def cache_info() -> Dict[str, int]:
    """Return cache statistics"""
    return {"cached_items": len(_CACHE)}
