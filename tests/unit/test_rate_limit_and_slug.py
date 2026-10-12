# Unit tests for the in-memory rate limiter and slug maker.
"""Unit tests for the in-memory rate limiter and slug generation."""

import time

from app.core.rate_limit import InMemoryRateLimiter
from app.modules.organizations.service import make_slug


def test_counts_hits_per_key() -> None:
    limiter = InMemoryRateLimiter()
    assert [limiter.hit("a", 60) for _ in range(3)] == [1, 2, 3]
    assert limiter.hit("b", 60) == 1  # other keys are independent


def test_window_resets_after_expiry() -> None:
    limiter = InMemoryRateLimiter()
    limiter.hit("a", 1)
    limiter.hit("a", 1)
    time.sleep(1.1)
    assert limiter.hit("a", 1) == 1


def test_slug_is_url_safe_and_unique() -> None:
    first, second = make_slug("ABC Insurance!!"), make_slug("ABC Insurance!!")
    assert first.startswith("abc-insurance-")
    assert first != second


def test_slug_falls_back_when_name_has_no_ascii_letters() -> None:
    assert make_slug("!!!").startswith("org-")
