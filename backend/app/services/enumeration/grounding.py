"""The grounding contract (Task 14): every candidate threat that reaches
adjudication must be *bound* to something real in the model and *cited*
by real technique evidence — never an agent's unverified assertion.

This check is meant to be enforced twice, deliberately: once inline as a
tool the Enumeration Agent's own handler calls to build its rejection log
(`app/services/enumeration/agent.py`), and once again, independently, as
the orchestrator's central `validate` gate (Task 1b) over the agent's
final output — "ungrounded steps always rejected... regardless of agent
output" means the second check must not simply trust the first.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.bridge import BridgedTechnique
from app.services.enumeration.engine import CandidateThreat
from app.services.systemmodel.models import SystemModel

DEFAULT_CITATION_THRESHOLD = 0.01

# Reason codes: stable, machine-checkable strings for the rejection log —
# never free-text-only, so a caller can filter/aggregate by failure class.
REASON_NO_ENTITY_BINDING = "no_entity_binding"
REASON_NO_FLOW_BINDING = "no_flow_binding"
REASON_NO_CITATION = "no_citation"


@dataclass(frozen=True)
class GroundingResult:
    satisfied: bool
    reason_code: str | None
    detail: str


def _known_entity_ids(model: SystemModel) -> set[str]:
    return {c.id for c in model.components}


def check_grounding(
    candidate: CandidateThreat,
    model: SystemModel,
    bridged_techniques: list[BridgedTechnique],
    citation_threshold: float = DEFAULT_CITATION_THRESHOLD,
) -> GroundingResult:
    known_ids = _known_entity_ids(model)

    if candidate.element_kind == "dataflow":
        flow = next((f for f in model.dataflows if f.id == candidate.element_id), None)
        if flow is None:
            return GroundingResult(
                False, REASON_NO_ENTITY_BINDING, f"no dataflow with id {candidate.element_id!r}"
            )
        if flow.source_id not in known_ids or flow.destination_id not in known_ids:
            return GroundingResult(
                False,
                REASON_NO_FLOW_BINDING,
                f"dataflow {flow.id!r} references unresolved endpoint(s): "
                f"source={flow.source_id!r} destination={flow.destination_id!r}",
            )
    else:
        if candidate.element_id not in known_ids:
            return GroundingResult(
                False,
                REASON_NO_ENTITY_BINDING,
                f"no component with id {candidate.element_id!r}",
            )

    if not any(t.fused_score >= citation_threshold for t in bridged_techniques):
        return GroundingResult(
            False,
            REASON_NO_CITATION,
            f"no bridged technique cleared the citation threshold ({citation_threshold})",
        )

    return GroundingResult(True, None, "entity/flow binding and citation both present")
