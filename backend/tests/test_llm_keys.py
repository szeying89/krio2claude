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


def test_reads_key_from_dotenv_file_when_no_real_env_var_is_set(monkeypatch, tmp_path):
    """Security-review-adjacent fix: app/core/config.py's Settings only
    loads .env for its own TM_-prefixed fields -- a provider key placed
    in .env was previously never found here."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-from-dotenv\n")
    assert get_api_key("anthropic") == "sk-ant-from-dotenv"


def test_a_real_env_var_takes_precedence_over_dotenv(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-real-env")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-from-dotenv\n")
    assert get_api_key("anthropic") == "sk-ant-from-real-env"


def test_dotenv_takes_precedence_over_keyring(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-from-dotenv\n")
    fake_keyring = types.SimpleNamespace(
        get_password=lambda service, account: "keyring-secret"
    )
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    assert get_api_key("anthropic") == "sk-ant-from-dotenv"


def test_missing_key_error_mentions_dotenv_as_an_option(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delitem(sys.modules, "keyring", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env file here
    with pytest.raises(MissingAPIKeyError, match="\\.env"):
        get_api_key("anthropic")
