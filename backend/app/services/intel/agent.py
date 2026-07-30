"""Intel Agent (Task 18): wires injection-indicator detection, LLM
extraction, and rule-based relevance matching into one `AgentSpec`.

The orchestrator's central `validate_intel_extraction` gate enforces "intel
can never mutate scope, tier, or rulesets" on two levels: structurally
(the agent's output has exactly three keys — `extracted_intel`,
`relevance`, `injection_indicators` — and there is no field anywhere in
this schema that could reach project scope, CRI tier, or the enumeration
ruleset) and by shape (every extracted technique id and CVE must match a
real ATT&CK/ATLAS or CVE identifier pattern, and `source_credibility` must
be one of the four allowed values) — so even an LLM that fully complies
with an injected instruction cannot get a fabricated, malformed, or
out-of-schema claim past this gate and into anything downstream.
"""

from __future__ import annotations

import re
from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.intel.extraction import extract_intel
from app.services.intel.injection_guard import detect_injection_indicators
from app.services.intel.models import ExtractedIntel
from app.services.intel.relevance import RelevanceResult, compute_relevance
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams

AGENT_NAME = "intel"

_TECHNIQUE_ID_RE = re.compile(r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ALLOWED_CREDIBILITY = {"high", "medium", "low", "unknown"}
_ALLOWED_OUTPUT_KEYS = {"extracted_intel", "relevance", "injection_indicators"}


def build_intel_agent(gateway: LLMGateway, params: CompletionParams) -> AgentSpec:
    """input_artifacts: `article_text: str`, optional `model: SystemModel`
    and `declared_sector: str | None` (relevance is only computed when a
    model is supplied — an article can be ingested/extracted before any
    project ever references it)."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        article_text: str = ctx.input_artifacts["article_text"]
        model = ctx.input_artifacts.get("model")
        declared_sector: str | None = ctx.input_artifacts.get("declared_sector")

        injection_indicators = ctx.call_tool(
            "intel.detect_injection_indicators", detect_injection_indicators, article_text
        )
        extracted: ExtractedIntel = ctx.call_tool(
            "intel.extract_intel", extract_intel, gateway, params, article_text
        )

        relevance: RelevanceResult | None = None
        if model is not None:
            relevance = ctx.call_tool(
                "intel.compute_relevance", compute_relevance, extracted, model, declared_sector
            )

        return {
            "extracted_intel": extracted,
            "relevance": relevance,
            "injection_indicators": injection_indicators,
        }

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("article_text",),
        output_artifact_types=("extracted_intel", "relevance", "injection_indicators"),
        handler=handler,
        max_tool_calls=50,
    )


def validate_intel_extraction(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    extra_keys = set(output_artifacts) - _ALLOWED_OUTPUT_KEYS
    if extra_keys:
        raise ValidationError(f"{agent_name}: unexpected output artifact keys {sorted(extra_keys)}")

    extracted = output_artifacts.get("extracted_intel")
    if extracted is None:
        return

    for technique_id in extracted.technique_ids:
        if not _TECHNIQUE_ID_RE.match(technique_id):
            raise ValidationError(
                f"{agent_name}: extracted technique id {technique_id!r} does not match a "
                "valid ATT&CK/ATLAS id shape"
            )
    for cve in extracted.cves:
        if not _CVE_RE.match(cve):
            raise ValidationError(
                f"{agent_name}: extracted CVE {cve!r} does not match the CVE-YYYY-NNNN shape"
            )
    if extracted.source_credibility not in _ALLOWED_CREDIBILITY:
        raise ValidationError(
            f"{agent_name}: source_credibility {extracted.source_credibility!r} is not one of "
            f"{sorted(_ALLOWED_CREDIBILITY)}"
        )
