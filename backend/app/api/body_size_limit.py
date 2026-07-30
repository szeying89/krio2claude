"""Security-review finding, fixed here: only file-upload endpoints had a
size cap (`TM_MAX_UPLOAD_BYTES`, checked incrementally while streaming).
Plain JSON request bodies had no ceiling at all anywhere in the stack --
reproduced directly: a single ~300 MB JSON body (an oversized
`scope_statements` list on `POST /projects`) was read into memory and
processed in full, no rejection anywhere.

This middleware rejects a request outright once its body exceeds
max_bytes. Well-behaved clients that send `Content-Length` are rejected
immediately, before a single byte of body is read. A request without
`Content-Length` (or one that understates it) is bounded by tracking the
running total as chunks arrive and aborting the read the moment the
total crosses the limit, rather than draining the rest of an
attacker-controlled body first.
"""

from __future__ import annotations

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        content_length = headers.get(b"content-length")
        if content_length is not None and int(content_length) > self.max_bytes:
            await self._reject(scope, receive, send)
            return

        total = 0

        async def limited_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    # Interrupts whatever loop inside the app is
                    # accumulating the body (e.g. Starlette's own
                    # Request.body()) immediately, instead of letting it
                    # keep pulling further chunks of an oversized body.
                    raise _BodyTooLargeError()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLargeError:
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = PlainTextResponse("request body too large", status_code=413)
        await response(scope, receive, send)
