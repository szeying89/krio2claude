"""Security-review finding, fixed here: this platform had no in-app
authentication or authorization at all -- every endpoint was reachable
by anyone who could reach the port, with loopback-only binding (Task
24's `assert_bind_allowed`) as the *only* control. That's a network-layer
mitigation, not an application one, and it's explicitly overridable via
`--allow-non-loopback`.

`require_api_key` is a real, enforced gate: when `TM_API_KEY` is set,
every request must carry a matching `X-API-Key` header, checked with a
constant-time comparison (`hmac.compare_digest`) so response timing can't
leak how many leading characters of a guess were correct. It is `None`
by default, preserving this build's existing documented behavior (and
every existing test's assumptions) exactly -- operators who want this
now have a real, built-in option instead of only "put a reverse proxy in
front of it."
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from app.core.config import get_settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    settings = get_settings()
    if settings.api_key is None:
        return
    if x_api_key is None or not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="missing or invalid API key")
