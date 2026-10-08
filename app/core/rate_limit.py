"""Rate limiting for abuse-prone endpoints (login, register, refresh).

Responsibility: count hits per key (e.g. an IP address) in a fixed time window
and reject callers who exceed the limit.

Two interchangeable backends behind one small interface:
- RedisRateLimiter: shared across all API processes (use in production).
- InMemoryRateLimiter: per-process; fine for local dev and tests, but NOT
  correct once you run more than one API instance.
"""

import threading
import time
from typing import Protocol

import redis

from app.core.config import get_settings
from app.core.errors import ErrorCode, RateLimitedError


class RateLimiter(Protocol):
    """Interface every backend implements."""

    def hit(self, key: str, window_seconds: int) -> int:
        """Record one hit for `key` and return how many hits the current window has."""
        ...


class InMemoryRateLimiter:
    """Fixed-window counter held in process memory (thread-safe)."""

    def __init__(self) -> None:
        """Create an empty limiter. `_windows` maps key -> (window_expires_at, count)."""
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, window_seconds: int) -> int:
        """Count a hit; start a new window if the previous one has expired.

        Args:
            key: what is being limited (e.g. "login:ip:1.2.3.4").
            window_seconds: window length.
        Returns:
            Hits so far in the current window, including this one.
        """
        now = time.monotonic()
        with self._lock:
            expires_at, count = self._windows.get(key, (0.0, 0))
            if now >= expires_at:
                expires_at, count = now + window_seconds, 0
            count += 1
            self._windows[key] = (expires_at, count)
            return count


class RedisRateLimiter:
    """Fixed-window counter stored in Redis so all API instances share it."""

    def __init__(self, client: "redis.Redis") -> None:
        """Wrap an existing Redis client (decode_responses=True)."""
        self._client = client

    def hit(self, key: str, window_seconds: int) -> int:
        """Atomically increment the key; set the expiry on the first hit.

        Edge case: if the process dies between INCR and EXPIRE the key would
        never expire, so we always (re)apply EXPIRE when the count is 1.
        """
        redis_key = f"ratelimit:{key}"
        count = int(self._client.incr(redis_key))
        if count == 1:
            self._client.expire(redis_key, window_seconds)
        return count


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """FastAPI dependency returning the process-wide limiter.

    Chooses Redis when REDIS_URL is configured, otherwise in-memory. Created
    lazily so importing this module never opens a network connection.
    Tests override this dependency to get an isolated limiter.
    """
    global _limiter
    if _limiter is None:
        redis_url = get_settings().redis_url
        _limiter = (
            RedisRateLimiter(redis.Redis.from_url(redis_url, decode_responses=True))
            if redis_url
            else InMemoryRateLimiter()
        )
    return _limiter


def enforce_rate_limit(limiter: RateLimiter, key: str) -> None:
    """Count a hit and raise if the caller is over the configured auth limit.

    Args:
        limiter: the backend to use.
        key: what to limit, e.g. f"login:ip:{ip}".
    Raises:
        RateLimitedError: when hits in the window exceed the configured maximum.
            The Retry-After header tells well-behaved clients when to retry.
    """
    settings = get_settings()
    window = settings.auth_rate_limit_window_seconds
    if limiter.hit(key, window) > settings.auth_rate_limit_attempts:
        raise RateLimitedError(
            ErrorCode.RATE_LIMITED,
            "Too many attempts. Please try again later.",
            headers={"Retry-After": str(window)},
        )
