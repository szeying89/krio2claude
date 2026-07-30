"""Security-review fix: app/api/body_size_limit.py::BodySizeLimitMiddleware
rejects a request outright once its body exceeds a configured ceiling.
Reproduced directly before this fix: a ~300 MB JSON body (an oversized
`scope_statements` list) was accepted and fully processed with no
rejection anywhere in the stack -- only file uploads had a size cap.
"""

from __future__ import annotations

import pytest

from app.api.body_size_limit import BodySizeLimitMiddleware


def _http_scope(*, content_length: int | None) -> dict:
    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode()))
    return {"type": "http", "method": "POST", "path": "/x", "headers": headers}


class _RecordingApp:
    """A minimal downstream ASGI app that drains the request body via
    repeated receive() calls (mirroring how Starlette's Request.body()
    behaves) and, if it ever gets that far, sends a 200."""

    def __init__(self) -> None:
        self.chunks_received: list[bytes] = []
        self.ran_to_completion = False

    async def __call__(self, scope, receive, send) -> None:
        while True:
            message = await receive()
            if message["type"] != "http.request":
                continue
            self.chunks_received.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        self.ran_to_completion = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _make_receive(chunks: list[bytes]):
    remaining = list(chunks)

    async def receive():
        if not remaining:
            return {"type": "http.request", "body": b"", "more_body": False}
        body = remaining.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(remaining)}

    return receive


def _make_send(collected: list[dict]):
    async def send(message: dict) -> None:
        collected.append(message)

    return send


@pytest.mark.asyncio
async def test_rejects_immediately_via_content_length_header_without_calling_the_app():
    app = _RecordingApp()
    middleware = BodySizeLimitMiddleware(app, max_bytes=100)
    scope = _http_scope(content_length=1000)
    sent: list[dict] = []

    await middleware(scope, _make_receive([b"x" * 1000]), _make_send(sent))

    assert not app.ran_to_completion
    assert app.chunks_received == []
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413


@pytest.mark.asyncio
async def test_passes_through_when_content_length_is_within_the_limit():
    app = _RecordingApp()
    middleware = BodySizeLimitMiddleware(app, max_bytes=1000)
    scope = _http_scope(content_length=10)
    sent: list[dict] = []

    await middleware(scope, _make_receive([b"x" * 10]), _make_send(sent))

    assert app.ran_to_completion
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200


@pytest.mark.asyncio
async def test_aborts_early_on_chunked_body_without_content_length_instead_of_draining_it():
    """No Content-Length header at all (e.g. chunked transfer encoding) --
    the middleware must still catch an oversized body by tracking the
    running total as chunks arrive, and must stop pulling further chunks
    the moment the limit is crossed rather than draining the rest first."""
    app = _RecordingApp()
    middleware = BodySizeLimitMiddleware(app, max_bytes=10)
    chunks = [b"x" * 5, b"x" * 5, b"x" * 5, b"x" * 5, b"x" * 5]  # 25 bytes total, well over 10
    scope = _http_scope(content_length=None)
    sent: list[dict] = []

    await middleware(scope, _make_receive(chunks), _make_send(sent))

    assert not app.ran_to_completion
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413
    # Aborted after the running total first crossed the limit (10 bytes,
    # crossed on the third 5-byte chunk) -- not after draining all 5.
    assert len(app.chunks_received) < 5


@pytest.mark.asyncio
async def test_non_http_scope_passes_through_untouched():
    calls: list[tuple] = []

    async def app(scope, receive, send) -> None:
        calls.append((scope, receive, send))

    middleware = BodySizeLimitMiddleware(app, max_bytes=10)
    scope = {"type": "lifespan"}

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message: dict) -> None:
        pass

    await middleware(scope, receive, send)
    assert len(calls) == 1
    assert calls[0][0] is scope


@pytest.mark.asyncio
async def test_oversized_json_body_is_rejected_via_the_real_app(app_env, monkeypatch):
    """End-to-end confirmation through the real app: the exact attack
    reproduced during the audit (an oversized JSON list field) now 413s
    instead of being fully parsed and processed.

    `max_bytes` is baked into the middleware at app-construction time
    (`create_app()` reads settings.max_request_body_bytes once), so this
    must build a fresh app after setting the env var rather than reuse
    the already-constructed `app.main.app` singleton the shared `client`
    fixture depends on."""
    monkeypatch.setenv("TM_MAX_REQUEST_BODY_BYTES", "500")
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/projects",
            json={
                "name": "demo",
                "business_criticality": "medium",
                "system_class": "it",
                "scope_statements": ["x" * 100 for _ in range(20)],  # well over 500 bytes
            },
        )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_ordinary_small_requests_are_unaffected(client):
    resp = await client.post(
        "/projects", json={"name": "demo", "business_criticality": "low", "system_class": "it"}
    )
    assert resp.status_code == 200
