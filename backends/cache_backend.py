import hashlib
import pickle
from typing import Dict, Any, Optional
from pathlib import Path

# Persistent cache file (moved to data/ folder)
CACHE_FILE = Path(__file__).parent.parent / "data" / "cache_data.pkl"

# Load cache from disk on import
if CACHE_FILE.exists():
    try:
        with open(CACHE_FILE, "rb") as f:
            _CACHE = pickle.load(f)
    except Exception:
        _CACHE = {}
else:
    _CACHE = {}


def _save_cache():
    """Save cache to disk"""
    try:
        with open(CACHE_FILE, "wb") as f:
            pickle.dump(_CACHE, f)
    except Exception as e:
        print(f"Warning: Failed to save cache: {e}")


def _make_key(text: str) -> str:
    return hashlib.sha256(text.lower().encode()).hexdigest()


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
