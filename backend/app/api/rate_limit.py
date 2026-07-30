"""Security-review finding: LLM-invoking endpoints (report generation,
review-item generation, revision creation) have no throttling at all --
each real LLM call has a real dollar cost, so repeated, unthrottled
calls are a business-logic-level denial-of-wallet risk, not just a
performance one.

A minimal in-memory sliding-window limiter, keyed by client IP. `None`
(the default) preserves this build's original unthrottled behavior
exactly, matching every existing test's assumption; setting
TM_RATE_LIMIT_PER_MINUTE turns on a real, enforced cap.
"""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import HTTPException, Request

from app.core.config import get_settings

_WINDOW_SECONDS = 60.0
_hits: dict[str, list[float]] = defaultdict(list)


def reset_rate_limits() -> None:
    """Test-only hook: clears all tracked request timestamps."""
    _hits.clear()


async def enforce_rate_limit(request: Request) -> None:
    settings = get_settings()
    limit = settings.rate_limit_per_minute
    if limit is None:
        return

    client_key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window_start = now - _WINDOW_SECONDS

    timestamps = _hits[client_key]
    while timestamps and timestamps[0] < window_start:
        timestamps.pop(0)

    if len(timestamps) >= limit:
        raise HTTPException(status_code=429, detail="rate limit exceeded, try again shortly")

    timestamps.append(now)
