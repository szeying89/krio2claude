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

Security-review finding, fixed here: `validate_url` and the actual
`httpx` connection each used to perform their *own*, independent DNS
resolution — `fetch.py` called `validate_url(url, resolve=...)` to check
a hostname, then separately called `client.get(url)`, which lets `httpx`
resolve the same hostname again via the system resolver moments later.
An attacker who controls DNS for the article's domain (a short TTL is
enough) can answer a public IP for the first lookup and a
loopback/private IP for the second — the classic "DNS rebinding" SSRF
bypass, and no amount of "resolve-then-check" logic closes it by itself,
since the two resolutions are inherently two separate points in time.
`PinnedResolutionTransport` (an `httpx.HTTPTransport` whose connections
resolve and validate the hostname *at actual connect time*, then dial the
validated IP directly) collapses the two steps into one atomic
operation, so there is no window in which a different DNS answer could
be substituted. TLS SNI and certificate hostname verification are
unaffected: `httpcore`'s own connection code sources `server_hostname`
for the TLS handshake from the request's original origin host,
independent of whatever literal address `connect_tcp` actually dialed
(verified directly against `httpcore`'s connection implementation, not
assumed) — this only changes *which IP the TCP socket connects to*, never
what the TLS layer verifies the certificate against.
"""

from __future__ import annotations

import ipaddress
import socket
import typing
from collections.abc import Callable
from urllib.parse import urlparse

import httpcore
import httpx

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


def _is_literal_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def resolve_and_validate(hostname: str, resolve: Resolver = default_resolver) -> list[str]:
    """Resolves `hostname` (or, if it's already a literal IP, uses it
    directly with no DNS lookup at all) and raises `SSRFBlockedError` if
    any resulting address is unsafe. Returns the validated address list
    so a caller that needs to actually connect can dial one of these
    exact addresses rather than re-resolving and risking a different
    answer (see `PinnedResolutionTransport`)."""
    ips = [hostname] if _is_literal_ip(hostname) else resolve(hostname)
    for ip_str in ips:
        if _is_blocked_ip(ip_str):
            raise SSRFBlockedError(f"host {hostname!r} resolves to disallowed address {ip_str!r}")
    return ips


def validate_url(url: str, resolve: Resolver = default_resolver) -> None:
    """Raises SSRFBlockedError if `url` is unsafe to fetch. A fast,
    early, fail-clearly check -- `PinnedResolutionTransport` is what
    actually closes the DNS-rebinding gap at connect time; this function
    additionally rejects disallowed schemes and malformed URLs before any
    connection is even attempted."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"scheme {parsed.scheme!r} is not allowed")
    if not parsed.hostname:
        raise SSRFBlockedError("URL has no hostname")

    resolve_and_validate(parsed.hostname, resolve)


class _ResolvingNetworkBackend(httpcore.NetworkBackend):
    """Wraps a real `NetworkBackend` (`httpcore.SyncBackend` by default;
    injectable for testing) but resolves and validates the target host
    itself, immediately before connecting, and dials the validated
    address directly -- so the address actually connected to is
    guaranteed to be the one just validated, not a second, independent
    resolution."""

    def __init__(self, resolve: Resolver, inner: httpcore.NetworkBackend | None = None) -> None:
        self._resolve = resolve
        self._inner = inner if inner is not None else httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        validated_ips = resolve_and_validate(host, self._resolve)
        return self._inner.connect_tcp(
            validated_ips[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        return self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class PinnedResolutionTransport(httpx.HTTPTransport):
    """An `httpx.HTTPTransport` whose connections resolve the target
    host through `resolve_and_validate` at the moment of connecting,
    rather than trusting a separate, earlier `validate_url` call plus
    `httpx`'s own independent resolution at request time. Reuses the
    parent class's own SSL-context/connection-pool construction --
    `network_backend` is the only thing that differs."""

    def __init__(self, resolve: Resolver, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context,
            network_backend=_ResolvingNetworkBackend(resolve),
        )
