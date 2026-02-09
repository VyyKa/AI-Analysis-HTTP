import hashlib

# cache giả lập (sau này thay bằng Redis / DB)
_CACHE = {}


def _make_key(text: str) -> str:
    return hashlib.sha256(text.lower().encode()).hexdigest()


def cache_get(text: str):
    key = _make_key(text)
    return _CACHE.get(key)


def cache_set(text: str, value: str):
    key = _make_key(text)
    _CACHE[key] = value
