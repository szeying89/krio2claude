"""A deterministic, no-network provider — used by tests and local
development (Mermaid-only / no-credentials mode) to exercise the gateway's
caching, repair-retry, and accounting logic without a real API key.

Never used for production correctness: it doesn't call an LLM at all, it
just returns pre-programmed or rule-based responses.
"""

from __future__ import annotations

from collections.abc import Callable

from app.services.llm.models import CompletionParams, LLMResponse, TokenUsage


class FakeProvider:
    name = "fake"

    def __init__(self, respond: Callable[[str], str] | None = None) -> None:
        self._respond = respond or (lambda prompt: prompt)
        self.calls: list[str] = []

    def complete(self, prompt: str, params: CompletionParams) -> LLMResponse:
        self.calls.append(prompt)
        text = self._respond(prompt)
        return LLMResponse(
            text=text,
            usage=TokenUsage(prompt_tokens=len(prompt.split()), completion_tokens=len(text.split())),
            model=params.model,
            raw={},
        )


def sequenced_fake_provider(responses: list[str]) -> FakeProvider:
    """A FakeProvider that returns each response in `responses` in order on
    successive calls — useful for testing the repair-retry loop (e.g. first
    response is invalid JSON, second is valid)."""
    iterator = iter(responses)

    def _respond(_prompt: str) -> str:
        try:
            return next(iterator)
        except StopIteration:
            return responses[-1] if responses else ""

    return FakeProvider(respond=_respond)
