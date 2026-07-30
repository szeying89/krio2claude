"""Enumeration Agent (Task 14): wires Tasks 10-13's deterministic tools
plus the grounding gate and applicability adjudication into a single
Task 1b `AgentSpec`. Every `CandidateThreat` `enumerate_threats` produces
ends up in exactly one of two places — `adjudicated_threats` (grounded,
given a verdict) or `rejection_log` (failed grounding, logged with a
reason code) — never both, never neither, which is what "no run completes
with unadjudicated candidates" requires.

The orchestrator's central `validate` gate (`validate_enumeration_grounding`
below) is a second, independent check over the agent's own output — see
`grounding.py`'s docstring for why this isn't redundant with the agent's
own inline check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.enumeration.adjudication import Adjudication, adjudicate
from app.services.enumeration.attack_graph import build_attack_graph
from app.services.enumeration.bridge import BridgedTechnique, TechniqueIndex, build_capec_bridge
from app.services.enumeration.engine import CandidateThreat, enumerate_threats
from app.services.enumeration.grounding import DEFAULT_CITATION_THRESHOLD, check_grounding
from app.services.enumeration.ruleset import Ruleset
from app.services.systemmodel.models import SystemModel

AGENT_NAME = "enumeration"


@dataclass(frozen=True)
class RejectionLogEntry:
    candidate_threat_id: str
    element_id: str
    category: str
    reason_code: str
    detail: str


def _element_kind_and_tags(candidate: CandidateThreat, model: SystemModel) -> tuple[str, tuple[str, ...]]:
    if candidate.element_kind == "dataflow":
        return "dataflow", ()
    component = next((c for c in model.components if c.id == candidate.element_id), None)
    return candidate.element_kind, (component.technology_tags if component else ())


def build_enumeration_agent(
    ruleset: Ruleset,
    index: TechniqueIndex | None,
    max_tool_calls: int = 5000,
) -> AgentSpec:
    def handler(ctx: AgentContext) -> dict[str, Any]:
        model: SystemModel = ctx.input_artifacts["model"]
        atlas_enabled: bool = ctx.input_artifacts.get("atlas_enabled", False)
        allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)

        candidates: list[CandidateThreat] = ctx.call_tool(
            "enumeration.enumerate_threats", enumerate_threats, model, ruleset
        )

        dataflow_candidates = [
            c for c in candidates if c.element_kind == "dataflow" and c.framework == "stride"
        ]
        attack_graph = ctx.call_tool(
            "enumeration.build_attack_graph",
            build_attack_graph,
            model,
            dataflow_candidates,
            index,
            allowed_matrices,
        )
        reachable_entity_ids = {n.entity_id for n in attack_graph.graph.nodes}

        adjudicated: list[Adjudication] = []
        rejection_log: list[RejectionLogEntry] = []

        for candidate in candidates:
            element_kind, tags = _element_kind_and_tags(candidate, model)
            bridged: list[BridgedTechnique] = (
                ctx.call_tool(
                    "enumeration.build_capec_bridge",
                    build_capec_bridge,
                    candidate.category,
                    element_kind,
                    tags,
                    index,
                    allowed_matrices,
                )
                if index is not None
                else []
            )

            grounding = ctx.call_tool(
                "enumeration.check_grounding", check_grounding, candidate, model, bridged
            )
            if not grounding.satisfied:
                rejection_log.append(
                    RejectionLogEntry(
                        candidate_threat_id=candidate.id,
                        element_id=candidate.element_id,
                        category=candidate.category,
                        reason_code=grounding.reason_code or "unknown",
                        detail=grounding.detail,
                    )
                )
                continue

            adjudicated.append(
                ctx.call_tool(
                    "enumeration.adjudicate", adjudicate, candidate, model, bridged, reachable_entity_ids
                )
            )

        return {
            "adjudicated_threats": adjudicated,
            "rejection_log": rejection_log,
            "candidate_count": len(candidates),
        }

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("system_model",),
        output_artifact_types=("adjudicated_threats", "rejection_log"),
        handler=handler,
        max_tool_calls=max_tool_calls,
    )


def validate_enumeration_grounding(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    """The orchestrator's central grounding gate: independently recomputes
    whether every adjudicated threat is actually grounded from data
    embedded in the agent's own output (citation score, evidence
    reference) — it does not trust the agent's verdict, so a bug in the
    agent's own inline filter can't silently let an ungrounded candidate
    through to adjudication."""
    for adjudication in output_artifacts.get("adjudicated_threats", []):
        if not adjudication.evidence_ref or adjudication.citation_score < DEFAULT_CITATION_THRESHOLD:
            raise ValidationError(
                f"{agent_name}: candidate {adjudication.candidate_threat_id!r} reached "
                f"adjudication without a grounding citation (evidence_ref={adjudication.evidence_ref!r}, "
                f"citation_score={adjudication.citation_score})"
            )

    adjudicated_ids = {a.candidate_threat_id for a in output_artifacts.get("adjudicated_threats", [])}
    rejected_ids = {r.candidate_threat_id for r in output_artifacts.get("rejection_log", [])}
    if adjudicated_ids & rejected_ids:
        raise ValidationError(
            f"{agent_name}: candidate(s) {adjudicated_ids & rejected_ids} appear in both "
            "adjudicated_threats and rejection_log"
        )
    total = output_artifacts.get("candidate_count")
    if total is not None and len(adjudicated_ids) + len(rejected_ids) != total:
        raise ValidationError(
            f"{agent_name}: {total} candidate(s) enumerated but only "
            f"{len(adjudicated_ids) + len(rejected_ids)} were adjudicated or rejected"
        )
