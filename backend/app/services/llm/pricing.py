"""Best-effort per-model pricing for cost accounting.

A snapshot, not load-bearing for correctness — verify against the
provider's current published pricing before relying on this for real
budget decisions. An unknown model returns a cost of 0.0 (visible as
"unpriced" rather than silently wrong) instead of guessing.
"""

from __future__ import annotations

from app.services.llm.models import TokenUsage

# model -> (input $ per 1M tokens, output $ per 1M tokens)
_PRICING_PER_MILLION_TOKENS_USD: dict[str, tuple[float, float]] = {
    "claude-opus-5": (15.0, 75.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (0.8, 4.0),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.6),
}


def estimate_cost_usd(model: str, usage: TokenUsage) -> float:
    pricing = _PRICING_PER_MILLION_TOKENS_USD.get(model)
    if pricing is None:
        return 0.0
    input_price, output_price = pricing
    return (usage.prompt_tokens / 1_000_000) * input_price + (
        usage.completion_tokens / 1_000_000
    ) * output_price


def is_priced(model: str) -> bool:
    return model in _PRICING_PER_MILLION_TOKENS_USD
