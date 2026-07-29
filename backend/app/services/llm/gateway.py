"""The LLM/Agent gateway: every call an agent makes to a hosted LLM goes
through here, never directly to a provider. Pins temperature 0 and other
params (Requirement 3: deterministic confidence rubric depends on
deterministic upstream behavior wherever possible), enforces a
content-addressed cache (cache hit = zero network calls, byte-identical
output), validates structured output against a Pydantic schema with a
bounded repair-retry loop, and accounts token cost — all before anything
is logged, with secrets redacted first.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from app.services.llm.cache import ContentAddressedCache, compute_cache_key
from app.services.llm.models import CompletionParams, TokenUsage
from app.services.llm.pricing import estimate_cost_usd
from app.services.llm.prompt_template import PromptTemplate
from app.services.llm.provider import LLMProvider
from app.services.llm.redaction import redact_secrets

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class DeterministicModeError(Exception):
    """Raised when the gateway is configured for Mermaid-only deterministic
    mode and something tries to make an LLM call anyway."""


class SchemaValidationFailedError(Exception):
    def __init__(self, message: str, raw_response: str, attempts: int) -> None:
        self.raw_response = raw_response
        self.attempts = attempts
        super().__init__(message)


@dataclass(frozen=True)
class GatewayResult:
    output: BaseModel
    cache_hit: bool
    usage: TokenUsage
    cost_usd: float
    attempts: int


class LLMGateway:
    def __init__(
        self,
        provider: LLMProvider | None,
        cache_dir: Path,
        deterministic_mode: bool = False,
        redact_before_send: bool = False,
    ) -> None:
        self.provider = provider
        self.cache = ContentAddressedCache(cache_dir)
        self.deterministic_mode = deterministic_mode
        self.redact_before_send = redact_before_send

    def complete_structured(
        self,
        template: PromptTemplate,
        variables: dict[str, str],
        schema: type[T],
        params: CompletionParams,
        kb_snapshot_hash: str | None = None,
        cri_snapshot_hash: str | None = None,
        max_repairs: int = 2,
    ) -> GatewayResult:
        if self.deterministic_mode:
            raise DeterministicModeError(
                "gateway is in Mermaid-only deterministic mode; no LLM calls are permitted "
                "— use a deterministic tool instead"
            )
        if self.provider is None:
            raise RuntimeError("no LLM provider configured on this gateway")

        prompt = template.render(**variables)
        prompt_to_send = redact_secrets(prompt).redacted_text if self.redact_before_send else prompt

        cache_key = compute_cache_key(
            prompt=f"{template.id}:{prompt_to_send}",
            model=params.model,
            params=params.to_dict(),
            kb_snapshot_hash=kb_snapshot_hash,
            cri_snapshot_hash=cri_snapshot_hash,
        )

        cached = self.cache.get(cache_key)
        if cached is not None:
            return GatewayResult(
                output=schema.model_validate(cached["output"]),
                cache_hit=True,
                usage=TokenUsage(**cached["usage"]),
                cost_usd=cached["cost_usd"],
                attempts=cached["attempts"],
            )

        attempts = 0
        current_prompt = prompt_to_send
        last_raw = ""
        last_error = ""
        total_usage = TokenUsage(0, 0)

        while attempts <= max_repairs:
            response = self.provider.complete(current_prompt, params)
            total_usage = TokenUsage(
                prompt_tokens=total_usage.prompt_tokens + response.usage.prompt_tokens,
                completion_tokens=total_usage.completion_tokens + response.usage.completion_tokens,
            )
            last_raw = response.text
            try:
                data = json.loads(response.text)
                output = schema.model_validate(data)
            except (json.JSONDecodeError, ValidationError) as exc:
                last_error = redact_secrets(str(exc)).redacted_text
                logger.warning("schema validation failed on attempt %d: %s", attempts + 1, last_error)
                attempts += 1
                current_prompt = (
                    f"{prompt_to_send}\n\nYour previous response did not match the required "
                    f"schema.\nError: {last_error}\nPrevious response:\n{redact_secrets(response.text).redacted_text}\n"
                    "Return ONLY corrected JSON matching the schema."
                )
                continue

            cost = estimate_cost_usd(params.model, total_usage)
            self.cache.put(
                cache_key,
                {
                    "output": output.model_dump(mode="json"),
                    "usage": {
                        "prompt_tokens": total_usage.prompt_tokens,
                        "completion_tokens": total_usage.completion_tokens,
                    },
                    "cost_usd": cost,
                    "attempts": attempts + 1,
                },
            )
            return GatewayResult(
                output=output, cache_hit=False, usage=total_usage, cost_usd=cost, attempts=attempts + 1
            )

        raise SchemaValidationFailedError(
            f"schema validation failed after {attempts} attempt(s): {last_error}",
            raw_response=last_raw,
            attempts=attempts,
        )
