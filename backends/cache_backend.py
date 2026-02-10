import hashlib
from typing import Dict, Any, Optional

# cache giả lập (sau này thay bằng Redis / DB)
_CACHE = {}


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


def cache_info() -> Dict[str, int]:
    """Return cache statistics"""
    return {"cached_items": len(_CACHE)}
