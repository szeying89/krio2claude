"""SSRF guard for Task 18's article-by-URL ingestion (the plan calls for
this to be "SSRF-guarded per Task 24" — Task 24 hasn't been reached yet in
this plan, so this module is a self-contained, real guard now, not a
placeholder; a later, more general Task 24 fetch-guard can supersede it,
but URL fetching driven by user/article input is unsafe to ship
unguarded in the meantime).

Two independent checks, both required: only `http`/`https` schemes are
ever fetched, and every hostname (the original URL's, and every redirect
hop's — `fetch.py` revalidates each hop before following it, never
trusting `httpx`'s own auto-redirect) must resolve to a public,
non-reserved address. A literal IP in the URL is checked the same way a
resolved DNS hostname is, so `http://127.0.0.1/...` and a hostname that
merely *resolves* to `127.0.0.1` are both blocked identically.

DNS resolution is injected via `resolve` (defaulting to real
`socket.getaddrinfo`) so tests can exercise the full IP-blocking decision
deterministically, with no real network/DNS dependency, by supplying a
fake resolver — the same dependency-injection pattern this plan uses for
`httpx.Client` (Task 3's fetchers) and the LLM provider (`FakeProvider`).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}

Resolver = Callable[[str], list[str]]


class SSRFBlockedError(Exception):
    pass


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def default_resolver(hostname: str) -> list[str]:
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"could not resolve host {hostname!r}: {exc}") from exc
    return [str(sockaddr[0]) for _family, _type, _proto, _canonname, sockaddr in addr_infos]


def validate_url(url: str, resolve: Resolver = default_resolver) -> None:
    """Raises SSRFBlockedError if `url` is unsafe to fetch."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"scheme {parsed.scheme!r} is not allowed")
    if not parsed.hostname:
        raise SSRFBlockedError("URL has no hostname")

    for ip_str in resolve(parsed.hostname):
        if _is_blocked_ip(ip_str):
            raise SSRFBlockedError(
                f"host {parsed.hostname!r} resolves to disallowed address {ip_str!r}"
            )
