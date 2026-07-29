import pytest

from app.services.intel.ssrf_guard import SSRFBlockedError, validate_url


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
