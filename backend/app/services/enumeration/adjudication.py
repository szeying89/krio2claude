"""Applicability adjudication (Task 14): every grounded candidate threat
gets adjudicated `applicable` or `not_applicable` with a structured
rationale, an evidence reference (the citation grounding already
established), and — critically for Task 19's re-evaluation diff — a
machine-readable `invalidation_condition` describing what new information
would overturn a `not_applicable` verdict. `applicable` verdicts carry no
invalidation_condition; there's nothing to invalidate a threat that's
already considered live.

Deterministic by design, consistent with the rest of Q2 (Tasks 10-13):
this platform has no LLM credentials configured in this sandbox anyway,
and an adjudication grounded purely in already-computed model/graph facts
is exactly as auditable and reproducible as everything upstream of it —
a real Enumeration Agent (once wired through Task 7's gateway) could
still supply a richer prose rationale later without changing this
function's contract.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.bridge import BridgedTechnique
from app.services.enumeration.engine import CandidateThreat
from app.services.systemmodel.models import SystemModel

VERDICT_APPLICABLE = "applicable"
VERDICT_NOT_APPLICABLE = "not_applicable"

INVALIDATION_OUT_OF_SCOPE = "out_of_scope_status_change"
INVALIDATION_REACHABILITY = "reachability"


@dataclass(frozen=True)
class InvalidationCondition:
    kind: str
    entity_id: str
    description: str


@dataclass(frozen=True)
class Adjudication:
    candidate_threat_id: str
    verdict: str
    rationale: str
    evidence_ref: str
    citation_score: float
    invalidation_condition: InvalidationCondition | None


def _best_evidence(bridged_techniques: list[BridgedTechnique]) -> tuple[str, float]:
    if not bridged_techniques:
        return "", 0.0
    best = max(bridged_techniques, key=lambda t: t.fused_score)
    return best.technique_id, best.fused_score


def _out_of_scope_entity(candidate: CandidateThreat, model: SystemModel) -> str | None:
    out_of_scope_ids = {c.id for c in model.components if c.out_of_scope}
    if candidate.element_kind == "dataflow":
        flow = next((f for f in model.dataflows if f.id == candidate.element_id), None)
        if flow is None:
            return None
        for entity_id in (flow.source_id, flow.destination_id):
            if entity_id in out_of_scope_ids:
                return entity_id
        return None
    return candidate.element_id if candidate.element_id in out_of_scope_ids else None


def _unreachable_entity(
    candidate: CandidateThreat, model: SystemModel, reachable_entity_ids: set[str]
) -> str | None:
    """Only STRIDE candidates depend on an attacker actually being able to
    reach the element — LINDDUN privacy risk exists in how data is
    handled regardless of whether an external attacker can get there, so
    it's exempt from this check entirely.

    Attack-graph nodes are always components, never dataflows, so a
    dataflow candidate is judged reachable by whether its *source*
    component is reachable (an attacker standing there could attempt to
    use this flow) — not by looking up the flow's own id, and not by
    requiring this exact (dataflow, category) pair to have won an edge
    slot in the collapsed graph, since a different candidate's technique
    may have won that slot while this flow is still real and traversable.
    """
    if candidate.framework != "stride":
        return None
    if candidate.element_kind == "dataflow":
        flow = next((f for f in model.dataflows if f.id == candidate.element_id), None)
        if flow is None or flow.source_id in reachable_entity_ids:
            return None
        return flow.source_id
    if candidate.element_id in reachable_entity_ids:
        return None
    return candidate.element_id


def adjudicate(
    candidate: CandidateThreat,
    model: SystemModel,
    bridged_techniques: list[BridgedTechnique],
    reachable_entity_ids: set[str],
) -> Adjudication:
    evidence_ref, citation_score = _best_evidence(bridged_techniques)

    out_of_scope_entity = _out_of_scope_entity(candidate, model)
    if out_of_scope_entity is not None:
        return Adjudication(
            candidate_threat_id=candidate.id,
            verdict=VERDICT_NOT_APPLICABLE,
            rationale=f"{out_of_scope_entity!r} is out of scope for this build "
            "(OT/ICS or mobile-client indicator detected)",
            evidence_ref=evidence_ref,
            citation_score=citation_score,
            invalidation_condition=InvalidationCondition(
                kind=INVALIDATION_OUT_OF_SCOPE,
                entity_id=out_of_scope_entity,
                description=f"would become applicable if {out_of_scope_entity!r}'s out-of-scope "
                "status is lifted (e.g. OT/mobile modelling support is added)",
            ),
        )

    unreachable_entity = _unreachable_entity(candidate, model, reachable_entity_ids)
    if unreachable_entity is not None:
        return Adjudication(
            candidate_threat_id=candidate.id,
            verdict=VERDICT_NOT_APPLICABLE,
            rationale=f"no attack-graph path from any in-scope external entry point reaches "
            f"{unreachable_entity!r} today",
            evidence_ref=evidence_ref,
            citation_score=citation_score,
            invalidation_condition=InvalidationCondition(
                kind=INVALIDATION_REACHABILITY,
                entity_id=unreachable_entity,
                description=f"would become applicable if a new dataflow connects an in-scope "
                f"external entry point to {unreachable_entity!r}",
            ),
        )

    return Adjudication(
        candidate_threat_id=candidate.id,
        verdict=VERDICT_APPLICABLE,
        rationale=f"grounded in real technique evidence ({evidence_ref}) and reachable from an "
        "in-scope external entry point"
        if candidate.framework == "stride"
        else f"grounded in real technique evidence ({evidence_ref}); LINDDUN privacy risk applies "
        "regardless of attacker reachability",
        evidence_ref=evidence_ref,
        citation_score=citation_score,
        invalidation_condition=None,
    )
