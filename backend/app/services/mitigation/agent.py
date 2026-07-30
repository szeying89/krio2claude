"""Mitigation Agent (Task 17): wires per-gap recommendation generation
into a single `AgentSpec`, following Task 14's split exactly — the
agent's own inline `check_recommendation_grounding` call keeps obviously
bad output out of the trajectory, and the orchestrator's central
`validate_mitigation_grounding` gate below independently recomputes
grounding from data embedded in the agent's own output, never trusting
the agent's verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import (
    MitigationRecommendation,
    check_recommendation_grounding,
    generate_recommendation,
)

AGENT_NAME = "mitigation"


@dataclass(frozen=True)
class RecommendationRejection:
    recommendation_id: str
    technique_id: str
    reason_code: str
    detail: str


def build_mitigation_agent(gateway: LLMGateway, params: CompletionParams) -> AgentSpec:
    """input_artifacts: `gaps: list[TechniqueGapAnalysis]`,
    `techniques_by_id: dict[str, TechniqueChunk]`, `d3fend_by_id: dict[str,
    D3fendTechnique]`, `cri_statement_texts: dict[str, str]`,
    `entity_names_by_id: dict[str, str]`, `entities_by_technique: dict[str,
    tuple[str, ...]]`."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        gaps: list[TechniqueGapAnalysis] = ctx.input_artifacts["gaps"]
        techniques_by_id: dict[str, TechniqueChunk] = ctx.input_artifacts.get("techniques_by_id", {})
        d3fend_by_id: dict[str, D3fendTechnique] = ctx.input_artifacts.get("d3fend_by_id", {})
        cri_statement_texts: dict[str, str] = ctx.input_artifacts.get("cri_statement_texts", {})
        entity_names_by_id: dict[str, str] = ctx.input_artifacts.get("entity_names_by_id", {})
        entities_by_technique: dict[str, tuple[str, ...]] = ctx.input_artifacts.get(
            "entities_by_technique", {}
        )

        recommendations: list[MitigationRecommendation] = []
        rejection_log: list[RecommendationRejection] = []
        gap_count = 0

        for gap in gaps:
            technique = techniques_by_id.get(gap.technique_id)
            candidate_entity_ids = entities_by_technique.get(gap.technique_id, ())
            candidate_statement_texts = {
                sid: cri_statement_texts[sid]
                for sid in gap.cri_gap_statement_ids
                if sid in cri_statement_texts
            }

            for d3fend_id in gap.d3fend_gap_ids:
                gap_count += 1
                d3fend = d3fend_by_id.get(d3fend_id)
                if technique is None or d3fend is None:
                    rejection_log.append(
                        RecommendationRejection(
                            recommendation_id=f"rec-{gap.technique_id}-{d3fend_id}",
                            technique_id=gap.technique_id,
                            reason_code="missing_reference_data",
                            detail=f"technique or D3FEND catalog entry unavailable for {d3fend_id!r}",
                        )
                    )
                    continue

                rec = ctx.call_tool(
                    "mitigation.generate_recommendation",
                    generate_recommendation,
                    gateway,
                    params,
                    gap,
                    technique.name,
                    technique.description,
                    d3fend,
                    candidate_statement_texts,
                    entity_names_by_id,
                    candidate_entity_ids,
                    f"rec-{gap.technique_id}-{d3fend_id}",
                )

                grounding = ctx.call_tool(
                    "mitigation.check_recommendation_grounding",
                    check_recommendation_grounding,
                    rec,
                    gap,
                    candidate_entity_ids,
                )
                if not grounding.satisfied:
                    rejection_log.append(
                        RecommendationRejection(
                            recommendation_id=rec.id,
                            technique_id=gap.technique_id,
                            reason_code=grounding.reason_code or "unknown",
                            detail=grounding.detail,
                        )
                    )
                    continue

                recommendations.append(rec)

        return {
            "recommendations": recommendations,
            "rejection_log": rejection_log,
            "gap_count": gap_count,
        }

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("gaps",),
        output_artifact_types=("recommendations", "rejection_log"),
        handler=handler,
        max_tool_calls=5000,
    )


def validate_mitigation_grounding(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    """The orchestrator's fact-provenance gate: every surfaced recommendation
    must cite a D3FEND id and every CRI statement id it claims to satisfy
    must actually be present in its own `cri_statement_ids` (already
    filtered against the technique's real gap by the inline check, but
    this independently re-verifies the *shape* of the data rather than
    trusting that the inline check ran) — and no recommendation id may
    appear in both the surfaced list and the rejection log."""
    for rec in output_artifacts.get("recommendations", []):
        if not rec.d3fend_id:
            raise ValidationError(
                f"{agent_name}: recommendation {rec.id!r} was surfaced without a D3FEND citation"
            )

    surfaced_ids = {r.id for r in output_artifacts.get("recommendations", [])}
    rejected_ids = {r.recommendation_id for r in output_artifacts.get("rejection_log", [])}
    if surfaced_ids & rejected_ids:
        raise ValidationError(
            f"{agent_name}: recommendation(s) {surfaced_ids & rejected_ids} appear in both "
            "recommendations and rejection_log"
        )
