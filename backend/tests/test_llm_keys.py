import sys
import types

import pytest

from app.services.llm.keys import MissingAPIKeyError, get_api_key


def test_reads_key_from_env_var(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-value")
    assert get_api_key("anthropic") == "sk-ant-test-value"


def test_provider_name_is_uppercased_for_env_lookup(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-value")
    assert get_api_key("openai") == "sk-test-value"


def test_missing_key_raises_without_leaking_any_value(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    with pytest.raises(MissingAPIKeyError) as exc_info:
        get_api_key("anthropic")
    message = str(exc_info.value)
    assert "anthropic" in message
    assert "ANTHROPIC_API_KEY" in message


def test_falls_back_to_keyring_when_env_var_absent(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake_keyring = types.SimpleNamespace(
        get_password=lambda service, account: "keyring-secret" if account == "anthropic" else None
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    assert get_api_key("anthropic") == "keyring-secret"


def test_keyring_miss_still_raises_missing_key_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake_keyring = types.SimpleNamespace(get_password=lambda service, account: None)
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    with pytest.raises(MissingAPIKeyError):
        get_api_key("anthropic")
