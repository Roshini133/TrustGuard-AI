"""Fixed-window rate limiter. Redis-backed when REDIS_URL is set (distributed); in-memory fallback otherwise.
Rate limiting is a protective control; if Redis is down we fall back to per-process memory rather than disabling."""
import logging
import threading
import time

from fastapi import HTTPException, Request

from .config import get_settings

log = logging.getLogger("trustguard.ratelimit")
_mem: dict[str, tuple[int, float]] = {}
_lock = threading.Lock()
_redis = None


def _get_redis():
    global _redis
    url = get_settings().REDIS_URL
    if not url:
        return None
    if _redis is None:
        import redis
        _redis = redis.Redis.from_url(url, socket_timeout=1.5, socket_connect_timeout=1.5)
    return _redis


def reset_memory():
    with _lock:
        _mem.clear()


def _parse(spec: str) -> tuple[int, int]:
    a, b = spec.split("/")
    return int(a), int(b)


def hit(key: str, limit: int, window: int) -> tuple[bool, int]:
    """Returns (allowed, retry_after_seconds)."""
    r = _get_redis()
    if r is not None:
        try:
            k = f"rl:{key}"
            n = r.incr(k)
            if n == 1:
                r.expire(k, window)
            if n > limit:
                ttl = r.ttl(k)
                return False, max(ttl, 1)
            return True, 0
        except Exception as e:
            log.warning("redis rate limit unavailable (%s); using memory", type(e).__name__)
    t = time.time()
    with _lock:
        n, start = _mem.get(key, (0, t))
        if t - start >= window:
            n, start = 0, t
        n += 1
        _mem[key] = (n, start)
        if n > limit:
            return False, int(window - (t - start)) + 1
    return True, 0


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce(bucket: str, spec: str, *identifiers: str):
    limit, window = _parse(spec)
    for ident in identifiers:
        if not ident:
            continue
        ok, retry = hit(f"{bucket}:{ident}", limit, window)
        if not ok:
            raise HTTPException(429, "Too many requests. Please try again later.", headers={"Retry-After": str(retry)})
