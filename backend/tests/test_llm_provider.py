import httpx
import pytest

from app.services.llm.models import CompletionParams
from app.services.llm.provider import (
    AnthropicProvider,
    BedrockProvider,
    OpenAIProvider,
    ProviderRequestError,
)


def _client_with_transport(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_anthropic_provider_parses_successful_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "secret-key"
        assert request.headers["anthropic-version"] == AnthropicProvider.API_VERSION
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "hello world"}],
                "usage": {"input_tokens": 12, "output_tokens": 3},
            },
        )

    provider = AnthropicProvider(api_key="secret-key", client=_client_with_transport(handler))
    result = provider.complete("hi", CompletionParams(model="claude-sonnet-5"))
    assert result.text == "hello world"
    assert result.usage.prompt_tokens == 12
    assert result.usage.completion_tokens == 3


def test_anthropic_provider_http_error_does_not_leak_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    provider = AnthropicProvider(api_key="super-secret-key", client=_client_with_transport(handler))
    with pytest.raises(ProviderRequestError) as exc_info:
        provider.complete("hi", CompletionParams(model="claude-sonnet-5"))
    assert "super-secret-key" not in str(exc_info.value)
    assert "401" in str(exc_info.value)


def test_anthropic_provider_network_error_does_not_leak_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed")

    provider = AnthropicProvider(api_key="super-secret-key", client=_client_with_transport(handler))
    with pytest.raises(ProviderRequestError) as exc_info:
        provider.complete("hi", CompletionParams(model="claude-sonnet-5"))
    assert "super-secret-key" not in str(exc_info.value)


def test_openai_provider_parses_successful_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret-key"
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "hello from openai"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            },
        )

    provider = OpenAIProvider(api_key="secret-key", client=_client_with_transport(handler))
    result = provider.complete("hi", CompletionParams(model="gpt-4o"))
    assert result.text == "hello from openai"
    assert result.usage.prompt_tokens == 5
    assert result.usage.completion_tokens == 2


def test_openai_provider_http_error_does_not_leak_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server error"})

    provider = OpenAIProvider(api_key="super-secret-key", client=_client_with_transport(handler))
    with pytest.raises(ProviderRequestError) as exc_info:
        provider.complete("hi", CompletionParams(model="gpt-4o"))
    assert "super-secret-key" not in str(exc_info.value)
    assert "500" in str(exc_info.value)


def test_bedrock_provider_is_explicitly_not_implemented():
    with pytest.raises(NotImplementedError):
        BedrockProvider()
