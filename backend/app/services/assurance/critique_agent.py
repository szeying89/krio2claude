"""Assurance Agent critique pass (Task 21) wired through the
orchestrator. The handler only ever calls read-only detector functions,
the LLM narrative generator, and the grounding check — there is no tool
in this agent's scope that edits `SystemModel` or persists anything;
`ctx.call_tool` is the *only* channel a handler has to affect the outside
world (Task 1b's own contract), and none of the tools registered here
are capable of mutation. `validate_critique_grounding` is the orchestrator's
central gate, independently re-verifying every surfaced item's citations
and severity, mirroring every other central gate in this plan.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.assurance.critique import (
    ReviewItem,
    check_review_item_grounding,
    generate_review_item,
)
from app.services.assurance.critique_detectors import (
    CandidateIssue,
    detect_missed_threats,
    detect_over_trusted_boundaries,
    detect_questionable_assumptions,
    detect_under_scoped_tiering,
    detect_weak_mitigations,
)
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams

AGENT_NAME = "critique"


def _item_id(candidate: CandidateIssue) -> str:
    payload = "|".join(
        [candidate.category, *candidate.cited_element_ids, *candidate.cited_statement_ids]
    )
    return "review-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_critique_agent(gateway: LLMGateway, params: CompletionParams) -> AgentSpec:
    """input_artifacts: `model`, `adjudicated_threats`, `gaps`,
    `entities_by_technique`, `assumptions`, `tier`, `cri_statements`."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        model = ctx.input_artifacts["model"]
        adjudicated_threats = ctx.input_artifacts.get("adjudicated_threats", [])
        gaps = ctx.input_artifacts.get("gaps", [])
        entities_by_technique = ctx.input_artifacts.get("entities_by_technique", {})
        assumptions = ctx.input_artifacts.get("assumptions", [])
        tier = ctx.input_artifacts.get("tier")
        cri_statements = ctx.input_artifacts.get("cri_statements", [])
        known_statement_ids = {s.profile_id for s in cri_statements}

        candidates: list[CandidateIssue] = []
        candidates += ctx.call_tool(
            "critique.detect_missed_threats", detect_missed_threats, model, adjudicated_threats
        )
        candidates += ctx.call_tool(
            "critique.detect_over_trusted_boundaries",
            detect_over_trusted_boundaries,
            model,
            adjudicated_threats,
        )
        candidates += ctx.call_tool(
            "critique.detect_weak_mitigations", detect_weak_mitigations, model, gaps, entities_by_technique
        )
        candidates += ctx.call_tool(
            "critique.detect_questionable_assumptions", detect_questionable_assumptions, assumptions
        )
        candidates += ctx.call_tool(
            "critique.detect_under_scoped_tiering", detect_under_scoped_tiering, tier, cri_statements
        )

        review_items: list[ReviewItem] = []
        rejection_log: list[dict[str, str]] = []

        for candidate in candidates:
            item_id = _item_id(candidate)
            item = ctx.call_tool(
                "critique.generate_review_item", generate_review_item, gateway, params, candidate, item_id
            )
            grounding = ctx.call_tool(
                "critique.check_review_item_grounding",
                check_review_item_grounding,
                item,
                model,
                known_statement_ids,
            )
            if not grounding.satisfied:
                rejection_log.append(
                    {
                        "candidate_id": item_id,
                        "category": candidate.category,
                        "reason_code": grounding.reason_code or "unknown",
                        "detail": grounding.detail,
                    }
                )
                continue
            review_items.append(item)

        return {
            "review_items": review_items,
            "rejection_log": rejection_log,
            "candidate_count": len(candidates),
        }

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("system_model",),
        output_artifact_types=("review_items", "rejection_log"),
        handler=handler,
        max_tool_calls=2000,
    )


def validate_critique_grounding(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    for item in output_artifacts.get("review_items", []):
        if not item.cited_element_ids and not item.cited_statement_ids:
            raise ValidationError(
                f"{agent_name}: review item {item.id!r} was surfaced without any citation"
            )

    surfaced_ids = {i.id for i in output_artifacts.get("review_items", [])}
    rejected_ids = {r["candidate_id"] for r in output_artifacts.get("rejection_log", [])}
    if surfaced_ids & rejected_ids:
        raise ValidationError(
            f"{agent_name}: item(s) {surfaced_ids & rejected_ids} appear in both "
            "review_items and rejection_log"
        )
