import asyncio
from collections.abc import AsyncIterator
from typing import Any


class EventBus:
    """Per-run pub/sub for SSE progress streaming.

    Kept in-process and per-run_id: this is a single-tenant, loopback-only
    local app (Requirement 1), not a distributed system, so an in-memory
    queue is sufficient and avoids a broker dependency.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}

    def subscribe(self, run_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.setdefault(run_id, []).append(queue)
        return queue

    def unsubscribe(self, run_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        subs = self._subscribers.get(run_id, [])
        if queue in subs:
            subs.remove(queue)
        if not subs:
            self._subscribers.pop(run_id, None)

    async def publish(self, run_id: str, event: dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(run_id, [])):
            await queue.put(event)

    async def stream(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        queue = self.subscribe(run_id)
        try:
            while True:
                event = await queue.get()
                yield event
                if event.get("type") == "run_status" and event.get("status") in (
                    "complete",
                    "failed",
                ):
                    return
        finally:
            self.unsubscribe(run_id, queue)


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Test-only hook: drop the cached EventBus for isolation between tests."""
    global _bus
    _bus = None
