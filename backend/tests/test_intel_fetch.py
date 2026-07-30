import httpx
import pytest

from app.services.intel.fetch import FetchError, fetch_article
from app.services.intel.ssrf_guard import SSRFBlockedError

PUBLIC_RESOLVE = lambda _h: ["93.184.216.34"]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_fetch_returns_body_text_and_final_url():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.com/article"
        return httpx.Response(200, text="hello world")

    text, final_url = fetch_article(
        "https://example.com/article", client=_client(handler), resolve=PUBLIC_RESOLVE
    )
    assert text == "hello world"
    assert final_url == "https://example.com/article"


def test_fetch_follows_a_redirect_and_revalidates_the_new_host():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if str(request.url) == "https://example.com/start":
            return httpx.Response(302, headers={"location": "https://example.com/final"})
        return httpx.Response(200, text="final content")

    text, final_url = fetch_article(
        "https://example.com/start", client=_client(handler), resolve=PUBLIC_RESOLVE
    )
    assert text == "final content"
    assert final_url == "https://example.com/final"
    assert calls == ["https://example.com/start", "https://example.com/final"]


def test_redirect_to_a_blocked_host_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://example.com/start":
            return httpx.Response(302, headers={"location": "http://internal.example/secret"})
        raise AssertionError("must never fetch the redirect target")

    def resolve(host: str) -> list[str]:
        return ["127.0.0.1"] if host == "internal.example" else ["93.184.216.34"]

    with pytest.raises(SSRFBlockedError):
        fetch_article("https://example.com/start", client=_client(handler), resolve=resolve)


def test_too_many_redirects_raises_fetch_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://example.com/next"})

    with pytest.raises(FetchError):
        fetch_article("https://example.com/start", client=_client(handler), resolve=PUBLIC_RESOLVE)


def test_oversized_response_is_rejected_by_patching_max_bytes(monkeypatch):
    import app.services.intel.fetch as fetch_module

    monkeypatch.setattr(fetch_module, "MAX_CONTENT_BYTES", 5)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="this response is too large")

    with pytest.raises(FetchError):
        fetch_article("https://example.com/big", client=_client(handler), resolve=PUBLIC_RESOLVE)


def test_oversized_response_is_rejected_via_content_length_before_any_body_is_read(monkeypatch):
    """A Content-Length header claiming an oversized body is rejected
    immediately -- proving the size cap is enforced before streaming the
    body, not only after buffering all of it (the fix for a response
    that could otherwise exhaust memory before the cap ever fired)."""
    import app.services.intel.fetch as fetch_module

    monkeypatch.setattr(fetch_module, "MAX_CONTENT_BYTES", 5)

    def handler(request: httpx.Request) -> httpx.Response:
        # The actual body is tiny; only the (lying) header claims huge.
        return httpx.Response(200, headers={"content-length": "99999999"}, text="ok")

    with pytest.raises(FetchError, match="exceeds max size"):
        fetch_article("https://example.com/big", client=_client(handler), resolve=PUBLIC_RESOLVE)


def test_oversized_response_with_no_content_length_is_still_caught_while_streaming(monkeypatch):
    """Without a Content-Length header at all (e.g. chunked transfer),
    the cap is still enforced -- incrementally, over the streamed body,
    not only via the header fast-path above."""
    import app.services.intel.fetch as fetch_module

    monkeypatch.setattr(fetch_module, "MAX_CONTENT_BYTES", 5)

    def handler(request: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, text="this response is too large")
        del response.headers["content-length"]
        return response

    with pytest.raises(FetchError, match="exceeds max size"):
        fetch_article("https://example.com/big", client=_client(handler), resolve=PUBLIC_RESOLVE)


def test_http_error_status_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    with pytest.raises(httpx.HTTPStatusError):
        fetch_article("https://example.com/missing", client=_client(handler), resolve=PUBLIC_RESOLVE)


def test_ssrf_guard_is_applied_before_the_first_request_too():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must never make a request to a blocked host")

    with pytest.raises(SSRFBlockedError):
        fetch_article(
            "http://169.254.169.254/latest/meta-data/",
            client=_client(handler),
            resolve=lambda _h: ["169.254.169.254"],
        )


def test_real_default_client_wires_in_pinned_resolution_without_error():
    """No injected client at all -- exercises fetch_article's own real
    default-client construction (PinnedResolutionTransport included),
    proving the wiring is valid Python/httpx, not just the mocked-client
    path every other test in this file uses. No real network call is
    made: the SSRF guard's early check rejects the blocked address before
    a connection would ever be attempted."""
    with pytest.raises(SSRFBlockedError):
        fetch_article(
            "http://169.254.169.254/latest/meta-data/",
            resolve=lambda _h: ["169.254.169.254"],
        )
