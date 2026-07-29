import pytest
from pydantic import BaseModel

from app.services.llm.fake_provider import FakeProvider, sequenced_fake_provider
from app.services.llm.gateway import (
    DeterministicModeError,
    LLMGateway,
    SchemaValidationFailedError,
)
from app.services.llm.models import CompletionParams
from app.services.llm.prompt_template import PromptTemplate


class Verdict(BaseModel):
    label: str
    confidence: float


TEMPLATE = PromptTemplate(name="classify", version="1", template="Classify: $text")
PARAMS = CompletionParams(model="fake-model")


def test_cache_miss_then_hit_is_byte_identical_with_zero_further_network_calls(tmp_path):
    provider = FakeProvider(respond=lambda _prompt: '{"label": "phishing", "confidence": 0.9}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    first = gateway.complete_structured(TEMPLATE, {"text": "an email"}, Verdict, PARAMS)
    assert first.cache_hit is False
    assert first.output == Verdict(label="phishing", confidence=0.9)
    assert len(provider.calls) == 1

    second = gateway.complete_structured(TEMPLATE, {"text": "an email"}, Verdict, PARAMS)
    assert second.cache_hit is True
    assert second.output == first.output
    assert second.usage == first.usage
    assert second.cost_usd == first.cost_usd
    # no further calls reached the provider on the cache hit
    assert len(provider.calls) == 1


def test_cache_hit_works_for_a_trajectory_shaped_payload(tmp_path):
    # The cache primitive doesn't care about payload shape — a full agent
    # trajectory (ordered steps + final output) round-trips the same way a
    # single completion does.
    provider = FakeProvider(
        respond=lambda _prompt: '{"label": "malware", "confidence": 0.75}'
    )
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")
    variables = {"text": "steps=[open,scan,report]"}

    first = gateway.complete_structured(TEMPLATE, variables, Verdict, PARAMS)
    second = gateway.complete_structured(TEMPLATE, variables, Verdict, PARAMS)
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert len(provider.calls) == 1


def test_different_variables_are_different_cache_entries(tmp_path):
    provider = FakeProvider(respond=lambda _prompt: '{"label": "x", "confidence": 0.5}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    gateway.complete_structured(TEMPLATE, {"text": "a"}, Verdict, PARAMS)
    gateway.complete_structured(TEMPLATE, {"text": "b"}, Verdict, PARAMS)
    assert len(provider.calls) == 2


def test_schema_violation_triggers_repair_then_succeeds(tmp_path):
    provider = sequenced_fake_provider(
        ["not json at all", '{"label": "benign", "confidence": 0.2}']
    )
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    result = gateway.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS)
    assert result.output == Verdict(label="benign", confidence=0.2)
    assert result.attempts == 2
    assert len(provider.calls) == 2
    # the repair prompt included the earlier failure so the provider had
    # something actionable to correct
    assert "schema" in provider.calls[1].lower()


def test_schema_violation_hard_fails_after_max_repairs_retaining_raw_response(tmp_path):
    provider = sequenced_fake_provider(["still not json", "still not json"])
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    with pytest.raises(SchemaValidationFailedError) as exc_info:
        gateway.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS, max_repairs=1)
    assert exc_info.value.raw_response == "still not json"
    assert exc_info.value.attempts == 2


def test_hard_failure_is_not_cached(tmp_path):
    cache_dir = tmp_path / "cache"
    failing_provider = sequenced_fake_provider(["bad", "bad"])
    gateway = LLMGateway(failing_provider, cache_dir=cache_dir)
    with pytest.raises(SchemaValidationFailedError):
        gateway.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS, max_repairs=1)

    # a fresh gateway sharing the same cache dir still has to call the
    # provider — nothing was persisted for a failed attempt
    recovering_provider = FakeProvider(respond=lambda _p: '{"label": "ok", "confidence": 1.0}')
    gateway2 = LLMGateway(recovering_provider, cache_dir=cache_dir)
    result = gateway2.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS)
    assert result.cache_hit is False
    assert len(recovering_provider.calls) == 1


def test_deterministic_mode_rejects_any_llm_call(tmp_path):
    gateway = LLMGateway(None, cache_dir=tmp_path / "cache", deterministic_mode=True)
    with pytest.raises(DeterministicModeError):
        gateway.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS)


def test_no_provider_configured_raises_runtime_error(tmp_path):
    gateway = LLMGateway(None, cache_dir=tmp_path / "cache")
    with pytest.raises(RuntimeError):
        gateway.complete_structured(TEMPLATE, {"text": "x"}, Verdict, PARAMS)


def test_redact_before_send_keeps_secret_out_of_provider_prompt(tmp_path):
    secret_template = PromptTemplate(name="leak", version="1", template="Key is $key. Classify.")
    provider = FakeProvider(respond=lambda _prompt: '{"label": "x", "confidence": 0.1}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache", redact_before_send=True)

    gateway.complete_structured(
        secret_template,
        {"key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"},
        Verdict,
        PARAMS,
    )
    assert len(provider.calls) == 1
    assert "sk-ant-api03" not in provider.calls[0]


def test_without_redact_before_send_prompt_is_sent_verbatim(tmp_path):
    secret_template = PromptTemplate(name="leak2", version="1", template="Key is $key. Classify.")
    provider = FakeProvider(respond=lambda _prompt: '{"label": "x", "confidence": 0.1}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache", redact_before_send=False)

    gateway.complete_structured(
        secret_template,
        {"key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"},
        Verdict,
        PARAMS,
    )
    assert "sk-ant-api03" in provider.calls[0]


def test_kb_and_cri_snapshot_hashes_participate_in_cache_key(tmp_path):
    provider = FakeProvider(respond=lambda _prompt: '{"label": "x", "confidence": 0.1}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    gateway.complete_structured(
        TEMPLATE, {"text": "a"}, Verdict, PARAMS, kb_snapshot_hash="hash-a"
    )
    gateway.complete_structured(
        TEMPLATE, {"text": "a"}, Verdict, PARAMS, kb_snapshot_hash="hash-b"
    )
    assert len(provider.calls) == 2
