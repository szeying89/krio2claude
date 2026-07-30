"""Provider abstraction (Requirement 2: hosted LLM API behind a provider
abstraction). Real Anthropic/OpenAI implementations are plain HTTPS calls
(no heavyweight SDK dependency) — untested against the live APIs in this
session because no API credentials are configured here, the same class of
gap as D3FEND/HuggingFace elsewhere in this plan: the code path is real and
ready, just unverified end-to-end from this sandbox. Bedrock requires
SigV4 request signing and is left as a documented not-yet-implemented
extension point rather than a half-working stub.

Every provider implements the same narrow `complete` method, so the
gateway (app/services/llm/gateway.py) never branches on which one is
configured.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from app.services.llm.models import CompletionParams, LLMResponse, TokenUsage


class LLMProvider(Protocol):
    name: str

    def complete(self, prompt: str, params: CompletionParams) -> LLMResponse: ...


class ProviderRequestError(Exception):
    """Wraps a provider HTTP failure. Deliberately does not include request
    headers in its message — the API key must never end up in a log line,
    a stored error, or a serialized exception."""


class AnthropicProvider:
    name = "anthropic"
    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client()

    def complete(self, prompt: str, params: CompletionParams) -> LLMResponse:
        try:
            response = self._client.post(
                self.API_URL,
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": self.API_VERSION,
                    "content-type": "application/json",
                },
                json={
                    "model": params.model,
                    "max_tokens": params.max_tokens,
                    "temperature": params.temperature,
                    "top_p": params.top_p,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=120.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderRequestError(
                f"Anthropic API request failed with status {exc.response.status_code}"
            ) from None
        except httpx.HTTPError as exc:
            raise ProviderRequestError(f"Anthropic API request failed: {type(exc).__name__}") from None

        data: dict[str, Any] = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", []))
        usage = data.get("usage", {})
        return LLMResponse(
            text=text,
            usage=TokenUsage(
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
            ),
            model=params.model,
            raw=data,
        )


class OpenAIProvider:
    name = "openai"
    API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client()

    def complete(self, prompt: str, params: CompletionParams) -> LLMResponse:
        try:
            response = self._client.post(
                self.API_URL,
                headers={
                    "authorization": f"Bearer {self._api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": params.model,
                    "max_tokens": params.max_tokens,
                    "temperature": params.temperature,
                    "top_p": params.top_p,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=120.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderRequestError(
                f"OpenAI API request failed with status {exc.response.status_code}"
            ) from None
        except httpx.HTTPError as exc:
            raise ProviderRequestError(f"OpenAI API request failed: {type(exc).__name__}") from None

        data: dict[str, Any] = response.json()
        choice = data.get("choices", [{}])[0]
        text = choice.get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return LLMResponse(
            text=text,
            usage=TokenUsage(
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
            ),
            model=params.model,
            raw=data,
        )


class BedrockProvider:
    """Not implemented: AWS Bedrock requires SigV4 request signing, which
    needs real AWS credentials to build and verify correctly — left as a
    documented extension point rather than a stub that looks functional but
    isn't. Raising here is deliberate, not an oversight."""

    name = "bedrock"

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError(
            "BedrockProvider is not implemented in this build; use AnthropicProvider "
            "or OpenAIProvider, or contribute a SigV4-signing implementation."
        )

    def complete(self, prompt: str, params: CompletionParams) -> LLMResponse:
        raise NotImplementedError
