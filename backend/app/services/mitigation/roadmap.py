"""Phased mitigation roadmap (Task 17): ranks each recommendation
independently by its own marginal risk reduction per unit of effort
(deterministic tie-break by recommendation id, so ordering never depends
on input order or dict iteration), then buckets the ranked list into
fixed-size phases and reports, per phase, the risk reduction it adds on
top of every previous phase, which CRI diagnostic statements it newly
satisfies, and which attack paths it fully closes (every technique on
that path left with zero D3FEND/CRI gap once every phase up to and
including this one is applied).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import PathEnumerationResult
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.residual_risk import apply_mitigations
from app.services.risk.register import build_risk_register

DEFAULT_PHASE_SIZE = 1


@dataclass(frozen=True)
class RoadmapPhase:
    phase_number: int
    recommendations: tuple[MitigationRecommendation, ...]
    cumulative_risk_reduction: float
    phase_risk_reduction: float
    diagnostic_statements_closed: tuple[str, ...]
    attack_paths_closed: tuple[str, ...]


def _total_score(
    path_result: PathEnumerationResult,
    gaps: list[TechniqueGapAnalysis],
    business_criticality: BusinessCriticality,
    tier: int | None,
    cri_statements: list[DiagnosticStatement],
    regulatory_documents: dict,
) -> float:
    register = build_risk_register(
        path_result, gaps, business_criticality, tier, cri_statements, regulatory_documents
    )
    return sum(f.score for f in register.findings)


def _has_gap(gap: TechniqueGapAnalysis | None) -> bool:
    return gap is not None and bool(gap.d3fend_gap_ids or gap.cri_gap_statement_ids)


def build_roadmap(
    path_result: PathEnumerationResult,
    gaps: list[TechniqueGapAnalysis],
    recommendations: list[MitigationRecommendation],
    business_criticality: BusinessCriticality,
    tier: int | None,
    cri_statements: list[DiagnosticStatement],
    regulatory_documents: dict,
    phase_size: int = DEFAULT_PHASE_SIZE,
) -> tuple[RoadmapPhase, ...]:
    if not recommendations:
        return ()

    def score_of(mitigated_gaps: list[TechniqueGapAnalysis]) -> float:
        return _total_score(
            path_result, mitigated_gaps, business_criticality, tier, cri_statements, regulatory_documents
        )

    baseline_total = score_of(gaps)

    ranked = []
    for rec in recommendations:
        candidate_total = score_of(apply_mitigations(gaps, [rec]))
        marginal_reduction = baseline_total - candidate_total
        ratio = marginal_reduction / max(rec.effort, 1)
        ranked.append((ratio, rec))
    ranked.sort(key=lambda pair: (-pair[0], pair[1].id))
    ordered_recs = [rec for _, rec in ranked]

    phases = []
    applied: list[MitigationRecommendation] = []
    previous_total = baseline_total

    for phase_number, start in enumerate(range(0, len(ordered_recs), phase_size), start=1):
        phase_recs = tuple(ordered_recs[start : start + phase_size])
        gaps_before = apply_mitigations(gaps, applied)
        before_by_technique = {g.technique_id: g for g in gaps_before}

        applied = applied + list(phase_recs)
        gaps_after = apply_mitigations(gaps, applied)
        after_by_technique = {g.technique_id: g for g in gaps_after}

        cumulative_total = score_of(gaps_after)

        closed_statements: set[str] = set()
        for technique_id, before_gap in before_by_technique.items():
            after_gap = after_by_technique.get(technique_id)
            if after_gap is None:
                continue
            closed_statements.update(
                set(before_gap.cri_gap_statement_ids) - set(after_gap.cri_gap_statement_ids)
            )

        closed_paths = []
        for path in path_result.paths:
            technique_ids = {step.technique_id for step in path.steps}
            had_gap_before = any(_has_gap(before_by_technique.get(tid)) for tid in technique_ids)
            fully_closed_after = not any(_has_gap(after_by_technique.get(tid)) for tid in technique_ids)
            if had_gap_before and fully_closed_after:
                closed_paths.append(path.id)

        phases.append(
            RoadmapPhase(
                phase_number=phase_number,
                recommendations=phase_recs,
                cumulative_risk_reduction=baseline_total - cumulative_total,
                phase_risk_reduction=previous_total - cumulative_total,
                diagnostic_statements_closed=tuple(sorted(closed_statements)),
                attack_paths_closed=tuple(sorted(closed_paths)),
            )
        )
        previous_total = cumulative_total

    return tuple(phases)
