from app.services.llm.models import TokenUsage
from app.services.llm.pricing import estimate_cost_usd, is_priced


def test_known_model_cost_computed_from_input_and_output_rates():
    usage = TokenUsage(prompt_tokens=1_000_000, completion_tokens=1_000_000)
    assert estimate_cost_usd("claude-sonnet-5", usage) == 3.0 + 15.0


def test_zero_usage_is_zero_cost():
    usage = TokenUsage(prompt_tokens=0, completion_tokens=0)
    assert estimate_cost_usd("claude-sonnet-5", usage) == 0.0


def test_unknown_model_returns_zero_not_a_guess():
    usage = TokenUsage(prompt_tokens=1_000_000, completion_tokens=1_000_000)
    assert estimate_cost_usd("some-future-model", usage) == 0.0


def test_is_priced_distinguishes_known_from_unknown():
    assert is_priced("claude-sonnet-5") is True
    assert is_priced("some-future-model") is False


def test_partial_tokens_scale_linearly():
    usage = TokenUsage(prompt_tokens=500_000, completion_tokens=0)
    assert estimate_cost_usd("gpt-4o-mini", usage) == 0.075
