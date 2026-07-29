"""Article-by-URL fetching (Task 18): validates the URL and every redirect
hop against `ssrf_guard.validate_url` before ever following it — `httpx`'s
own automatic redirect-following is deliberately disabled
(`follow_redirects=False`) so a redirect can never bypass the guard.
"""

from __future__ import annotations

import httpx

from app.services.intel.ssrf_guard import Resolver, default_resolver, validate_url

MAX_CONTENT_BYTES = 5_000_000
MAX_REDIRECTS = 5
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    pass


def fetch_article(
    url: str,
    client: httpx.Client | None = None,
    resolve: Resolver = default_resolver,
) -> tuple[str, str]:
    """Returns (content_text, final_url)."""
    owns_client = client is None
    client = client or httpx.Client(follow_redirects=False, timeout=10.0)
    try:
        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_url(current_url, resolve=resolve)
            response = client.get(current_url)

            if response.status_code in _REDIRECT_STATUS_CODES:
                location = response.headers.get("location")
                if not location:
                    raise FetchError(f"redirect from {current_url!r} has no Location header")
                current_url = str(httpx.URL(current_url).join(location))
                continue

            response.raise_for_status()
            if len(response.content) > MAX_CONTENT_BYTES:
                raise FetchError(f"response from {current_url!r} exceeds max size")
            return response.text, current_url

        raise FetchError(f"too many redirects starting from {url!r}")
    finally:
        if owns_client:
            client.close()
