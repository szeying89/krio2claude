"""Task 21's five deterministic critique detectors — one per category the
plan names ("missed threats, weak mitigations, questionable assumptions,
over-trusted boundaries, and under-scoped tiering"). Every detector
identifies its own citations (element/statement ids) itself; nothing here
ever asks an LLM to supply an id, mirroring Task 17's D3FEND-id split —
the LLM only ever writes severity/rationale narrative in `critique.py`,
never the identifiers that let a finding into the review queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.adjudication import VERDICT_NOT_APPLICABLE, Adjudication
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.modelbuilding.models import Assumption
from app.services.systemmodel.models import SystemModel

CATEGORY_MISSED_THREAT = "missed_threat"
CATEGORY_WEAK_MITIGATION = "weak_mitigation"
CATEGORY_QUESTIONABLE_ASSUMPTION = "questionable_assumption"
CATEGORY_OVER_TRUSTED_BOUNDARY = "over_trusted_boundary"
CATEGORY_UNDER_SCOPED_TIERING = "under_scoped_tiering"

LOW_CONFIDENCE_THRESHOLD = 0.5


@dataclass(frozen=True)
class CandidateIssue:
    category: str
    cited_element_ids: tuple[str, ...]
    cited_statement_ids: tuple[str, ...] = field(default_factory=tuple)
    context: str = ""


def detect_missed_threats(model: SystemModel, adjudicated_threats: list[Adjudication]) -> list[CandidateIssue]:
    """A dataflow that crosses a trust-zone boundary but has zero
    adjudicated verdicts at all — every one of its own candidates, if
    any were even enumerated, failed grounding rather than reaching a
    verdict either way."""
    zone_by_component = {c.id: c.trust_zone_id for c in model.components}
    adjudicated_element_ids = {a.candidate_threat_id.split("::")[0] for a in adjudicated_threats}

    issues = []
    for flow in model.dataflows:
        source_zone = zone_by_component.get(flow.source_id)
        dest_zone = zone_by_component.get(flow.destination_id)
        if source_zone is None or dest_zone is None or source_zone == dest_zone:
            continue
        if flow.id in adjudicated_element_ids:
            continue
        issues.append(
            CandidateIssue(
                category=CATEGORY_MISSED_THREAT,
                cited_element_ids=(flow.id, flow.source_id, flow.destination_id),
                context=f"dataflow {flow.name or flow.id!r} crosses from trust zone {source_zone!r} "
                f"to {dest_zone!r} with no adjudicated threat at all",
            )
        )
    return issues


def detect_over_trusted_boundaries(
    model: SystemModel, adjudicated_threats: list[Adjudication]
) -> list[CandidateIssue]:
    """A dataflow crossing into a *more* trusted zone whose own STRIDE
    verdicts are all `not_applicable` — an attacker path into a more
    trusted zone judged entirely unreachable is exactly the kind of
    boundary a human should double-check, not accept silently."""
    trust_rating_by_component = {}
    zone_rating = {z.id: z.trust_rating for z in model.trust_zones}
    for component in model.components:
        trust_rating_by_component[component.id] = zone_rating.get(component.trust_zone_id)

    verdicts_by_element: dict[str, list[str]] = {}
    for adjudication in adjudicated_threats:
        element_id = adjudication.candidate_threat_id.split("::")[0]
        verdicts_by_element.setdefault(element_id, []).append(adjudication.verdict)

    issues = []
    for flow in model.dataflows:
        source_rating = trust_rating_by_component.get(flow.source_id)
        dest_rating = trust_rating_by_component.get(flow.destination_id)
        if source_rating is None or dest_rating is None or dest_rating <= source_rating:
            continue
        verdicts = verdicts_by_element.get(flow.id, [])
        if verdicts and all(v == VERDICT_NOT_APPLICABLE for v in verdicts):
            issues.append(
                CandidateIssue(
                    category=CATEGORY_OVER_TRUSTED_BOUNDARY,
                    cited_element_ids=(flow.id, flow.destination_id),
                    context=f"dataflow {flow.name or flow.id!r} crosses into a more trusted zone "
                    f"(rating {source_rating} -> {dest_rating}) yet every adjudicated threat on it "
                    "was judged not_applicable",
                )
            )
    return issues


def detect_weak_mitigations(
    model: SystemModel,
    gaps: list[TechniqueGapAnalysis],
    entities_by_technique: dict[str, tuple[str, ...]],
) -> list[CandidateIssue]:
    """A declared control that applies to an entity actually touched by a
    technique (via that technique's own attack-path steps), yet the
    technique still has an open D3FEND or CRI gap — the control exists
    but doesn't actually close what it's supposed to for that entity."""
    issues = []
    for control in model.declared_controls:
        if not control.applies_to_ids:
            continue
        for gap in gaps:
            if not (gap.d3fend_gap_ids or gap.cri_gap_statement_ids):
                continue
            technique_entities = set(entities_by_technique.get(gap.technique_id, ()))
            covered_entities = technique_entities & set(control.applies_to_ids)
            if not covered_entities:
                continue
            issues.append(
                CandidateIssue(
                    category=CATEGORY_WEAK_MITIGATION,
                    cited_element_ids=tuple(sorted(covered_entities)),
                    context=f"control {control.id!r} ({control.name!r}) applies to "
                    f"{sorted(covered_entities)} but "
                    f"technique {gap.technique_id} still has open gap(s) there: "
                    f"D3FEND {gap.d3fend_gap_ids}, CRI {gap.cri_gap_statement_ids}",
                )
            )
    return issues


def detect_questionable_assumptions(assumptions: list[Assumption]) -> list[CandidateIssue]:
    return [
        CandidateIssue(
            category=CATEGORY_QUESTIONABLE_ASSUMPTION,
            cited_element_ids=(a.subject_id,),
            context=f"assumption {a.message!r} was made with only {a.confidence:.2f} confidence "
            f"(impact if wrong: {a.impact_if_wrong})",
        )
        for a in assumptions
        if a.confidence < LOW_CONFIDENCE_THRESHOLD
    ]


def detect_under_scoped_tiering(
    tier: int | None, cri_statements: list[DiagnosticStatement]
) -> list[CandidateIssue]:
    """If the project's current tier excludes a statement that would be
    in scope at a stricter tier, that statement is real, cite-able
    evidence that tightening the tier would surface more requirements —
    fires only when there is a real statement to cite, never on a bare
    "no tiering yet" observation with nothing to ground it in."""
    if tier is None or tier <= 1:
        return []
    issues = []
    for statement in cri_statements:
        if tier in statement.applicable_tiers:
            continue
        if any(t < tier for t in statement.applicable_tiers):
            issues.append(
                CandidateIssue(
                    category=CATEGORY_UNDER_SCOPED_TIERING,
                    cited_element_ids=(),
                    cited_statement_ids=(statement.profile_id,),
                    context=f"statement {statement.profile_id!r} ({statement.name}) applies at a "
                    f"stricter tier than the project's current tier {tier}, and so is currently "
                    "out of scope",
                )
            )
    return issues
