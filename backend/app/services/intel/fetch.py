"""Article-by-URL fetching (Task 18): validates the URL and every redirect
hop against `ssrf_guard.validate_url` before ever following it — `httpx`'s
own automatic redirect-following is deliberately disabled
(`follow_redirects=False`) so a redirect can never bypass the guard.

Security-review findings, fixed here:

- The default client now connects through `PinnedResolutionTransport`,
  which resolves and validates each hostname at the moment of actually
  connecting rather than trusting `validate_url`'s earlier, separate
  resolution -- closing a DNS-rebinding TOCTOU window where an attacker
  controlling DNS for the article's domain could answer a safe address
  for the early check and an internal one for the real connection.
- The response body is now streamed and the size cap enforced
  incrementally, aborting as soon as `MAX_CONTENT_BYTES` is exceeded,
  instead of downloading the full body into memory before checking its
  length -- a malicious or compromised source could previously exhaust
  memory with an oversized response before the check ever ran.
"""

from __future__ import annotations

import httpx

from app.services.intel.ssrf_guard import (
    PinnedResolutionTransport,
    Resolver,
    default_resolver,
    validate_url,
)

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
    client = client or httpx.Client(
        follow_redirects=False,
        timeout=10.0,
        transport=PinnedResolutionTransport(resolve=resolve),
    )
    try:
        current_url = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_url(current_url, resolve=resolve)

            with client.stream("GET", current_url) as response:
                if response.status_code in _REDIRECT_STATUS_CODES:
                    location = response.headers.get("location")
                    if not location:
                        raise FetchError(f"redirect from {current_url!r} has no Location header")
                    current_url = str(httpx.URL(current_url).join(location))
                    continue

                response.raise_for_status()

                content_length = response.headers.get("content-length")
                if content_length is not None and int(content_length) > MAX_CONTENT_BYTES:
                    raise FetchError(f"response from {current_url!r} exceeds max size")

                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_CONTENT_BYTES:
                        raise FetchError(f"response from {current_url!r} exceeds max size")

                text = bytes(body).decode(response.charset_encoding or "utf-8", errors="replace")
                return text, current_url

        raise FetchError(f"too many redirects starting from {url!r}")
    finally:
        if owns_client:
            client.close()
