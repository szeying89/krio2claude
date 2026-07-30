import httpcore
import pytest

from app.services.intel.ssrf_guard import (
    PinnedResolutionTransport,
    SSRFBlockedError,
    _ResolvingNetworkBackend,
    validate_url,
)


def test_rejects_non_http_scheme():
    with pytest.raises(SSRFBlockedError):
        validate_url("file:///etc/passwd", resolve=lambda _h: ["93.184.216.34"])


def test_rejects_url_with_no_hostname():
    with pytest.raises(SSRFBlockedError):
        validate_url("https://", resolve=lambda _h: ["93.184.216.34"])


def test_allows_public_ipv4_address():
    validate_url("https://example.com/article", resolve=lambda _h: ["93.184.216.34"])


def test_blocks_loopback_address():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://malicious.example/", resolve=lambda _h: ["127.0.0.1"])


def test_blocks_private_rfc1918_address():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://internal.example/", resolve=lambda _h: ["10.0.0.5"])


def test_blocks_link_local_address():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://metadata.example/", resolve=lambda _h: ["169.254.169.254"])


def test_blocks_ipv6_loopback():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://v6.example/", resolve=lambda _h: ["::1"])


def test_blocks_ipv6_unique_local():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://v6.example/", resolve=lambda _h: ["fc00::1"])


def test_blocks_if_any_resolved_address_is_disallowed():
    # A hostname resolving to multiple addresses is blocked if even one is unsafe.
    with pytest.raises(SSRFBlockedError):
        validate_url("https://multi.example/", resolve=lambda _h: ["93.184.216.34", "127.0.0.1"])


def test_literal_private_ip_in_url_is_blocked_without_dns():
    with pytest.raises(SSRFBlockedError):
        validate_url("http://127.0.0.1:8080/admin", resolve=lambda _h: ["127.0.0.1"])


# -- DNS-rebinding fix: PinnedResolutionTransport / _ResolvingNetworkBackend --
#
# validate_url() and the actual connection used to each resolve the
# hostname independently, leaving a window in which an attacker
# controlling DNS could answer differently between the two lookups (the
# classic "DNS rebinding" SSRF bypass). _ResolvingNetworkBackend collapses
# resolution and connection into one atomic step, at the exact moment the
# TCP socket is about to be opened -- these tests verify it actually
# connects to the *validated* address, never falls back to the original
# hostname, and never even attempts a connection when the resolved
# address is unsafe, using a fake inner backend so no real socket is ever
# opened.


class _RecordingBackend(httpcore.NetworkBackend):
    """A fake inner NetworkBackend that never actually connects -- it
    just records what host/port it was asked to dial and raises, so the
    test can assert on the call without any real networking."""

    class _Called(Exception):
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        raise self._Called(host, port)


def test_resolving_backend_connects_to_the_validated_ip_not_the_hostname():
    inner = _RecordingBackend()
    backend = _ResolvingNetworkBackend(resolve=lambda _h: ["93.184.216.34"], inner=inner)

    with pytest.raises(_RecordingBackend._Called):
        backend.connect_tcp("example.com", 443)

    assert inner.calls == [("93.184.216.34", 443)]


def test_resolving_backend_rejects_an_unsafe_resolved_address_before_connecting():
    inner = _RecordingBackend()
    backend = _ResolvingNetworkBackend(resolve=lambda _h: ["127.0.0.1"], inner=inner)

    with pytest.raises(SSRFBlockedError):
        backend.connect_tcp("internal.example", 80)

    assert inner.calls == [], "must never attempt a connection once the address is rejected"


def test_resolving_backend_treats_a_literal_ip_host_the_same_way():
    inner = _RecordingBackend()
    backend = _ResolvingNetworkBackend(resolve=lambda _h: ["203.0.113.5"], inner=inner)

    with pytest.raises(SSRFBlockedError):
        backend.connect_tcp("169.254.169.254", 80)

    assert inner.calls == []


def test_pinned_resolution_transport_actually_wires_in_the_resolving_backend():
    """A structural guarantee that the pinning is really plumbed into the
    transport httpx will use, not merely present in an unused helper
    class."""
    transport = PinnedResolutionTransport(resolve=lambda _h: ["93.184.216.34"])
    assert isinstance(transport._pool._network_backend, _ResolvingNetworkBackend)
