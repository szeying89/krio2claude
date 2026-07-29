"""Residual risk (Task 17): a deterministic tool, not something the
Mitigation Agent's own reasoning can override — re-scores every path
exactly as Task 16 does, but against gap records with each accepted
recommendation's cited D3FEND id and CRI statement ids removed from the
technique's own gap sets first. Never mutates the input gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import PathEnumerationResult
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.risk.models import RiskRegister
from app.services.risk.register import build_risk_register


def apply_mitigations(
    gaps: list[TechniqueGapAnalysis],
    recommendations: list[MitigationRecommendation],
) -> list[TechniqueGapAnalysis]:
    d3fend_closed_by_technique: dict[str, set[str]] = {}
    cri_closed_by_technique: dict[str, set[str]] = {}
    for rec in recommendations:
        d3fend_closed_by_technique.setdefault(rec.technique_id, set()).add(rec.d3fend_id)
        cri_closed_by_technique.setdefault(rec.technique_id, set()).update(rec.cri_statement_ids)

    mitigated = []
    for gap in gaps:
        closed_d3fend = d3fend_closed_by_technique.get(gap.technique_id, set())
        closed_cri = cri_closed_by_technique.get(gap.technique_id, set())
        if not closed_d3fend and not closed_cri:
            mitigated.append(gap)
            continue
        mitigated.append(
            replace(
                gap,
                d3fend_gap_ids=tuple(
                    sorted(set(gap.d3fend_gap_ids) - closed_d3fend)
                ),
                cri_gap_statement_ids=tuple(
                    sorted(set(gap.cri_gap_statement_ids) - closed_cri)
                ),
            )
        )
    return mitigated


@dataclass(frozen=True)
class ResidualRiskComparison:
    baseline: RiskRegister
    residual: RiskRegister
    baseline_total_score: float
    residual_total_score: float
    risk_reduction: float


def compute_residual_risk(
    path_result: PathEnumerationResult,
    gaps: list[TechniqueGapAnalysis],
    recommendations: list[MitigationRecommendation],
    business_criticality: BusinessCriticality,
    tier: int | None,
    cri_statements: list[DiagnosticStatement],
    regulatory_documents: dict,
) -> ResidualRiskComparison:
    baseline = build_risk_register(
        path_result, gaps, business_criticality, tier, cri_statements, regulatory_documents
    )
    mitigated_gaps = apply_mitigations(gaps, recommendations)
    residual = build_risk_register(
        path_result, mitigated_gaps, business_criticality, tier, cri_statements, regulatory_documents
    )

    baseline_total = sum(f.score for f in baseline.findings)
    residual_total = sum(f.score for f in residual.findings)

    return ResidualRiskComparison(
        baseline=baseline,
        residual=residual,
        baseline_total_score=baseline_total,
        residual_total_score=residual_total,
        risk_reduction=baseline_total - residual_total,
    )
