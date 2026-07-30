from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TokenUsage:
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True)
class CompletionParams:
    """Pinned, deterministic completion parameters — temperature 0 by
    default, matching the plan's determinism requirement. Every field that
    can affect output must be included in `to_dict()` since that feeds the
    cache key: two calls with different params are different cache entries."""

    model: str
    temperature: float = 0.0
    max_tokens: int = 4096
    top_p: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
        }


@dataclass(frozen=True)
class LLMResponse:
    text: str
    usage: TokenUsage
    model: str
    raw: dict[str, Any] = field(default_factory=dict)
