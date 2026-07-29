"""Deterministic risk formula (Task 16): `score = likelihood * impact_weight
* (1 + statement_density)`.

`likelihood` is Task 13's own `AttackPath.aggregate_likelihood` — already a
per-path probability estimate, never re-derived here.

`impact_weight` combines two independent signals: the project's own
declared `business_criticality` (set at project creation, always present,
independent of CRI) and, when a CRI Impact Tier has actually been
computed for this project, a tier multiplier on top of it. A finding
against a Tier-1 institution's system is judged more consequential than
the identical finding against an untiered or Tier-4 one; a project with
no CRI profile (or no tiering questionnaire answered yet) still gets a
real, non-zero impact weight from its own declared criticality alone —
this is exactly the "likelihood/impact-only" degraded mode the plan asks
for, not a placeholder value.

`statement_density` is the fraction of a finding's in-tier CRI
requirements that are currently unsatisfied (0 when the project has no
CRI data at all, or when none of the finding's techniques carry any CRI
mapping) — "unsatisfied-statement density" from the plan. It is a
multiplicative bonus on top of likelihood*impact, never a replacement for
either: a finding with dense control debt is judged more (not
differently) risky than the same finding with the debt closed.
"""

from __future__ import annotations

from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import AttackPath
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.risk.csf import csf_function_code
from app.services.risk.models import RegulatoryExposure, RiskFactors, RiskFinding

BUSINESS_CRITICALITY_WEIGHT: dict[BusinessCriticality, float] = {
    BusinessCriticality.LOW: 0.25,
    BusinessCriticality.MEDIUM: 0.5,
    BusinessCriticality.HIGH: 0.75,
    BusinessCriticality.CRITICAL: 1.0,
}

# Only applied when a CRI Impact Tier has actually been computed; the
# project's own business_criticality is the impact signal otherwise.
TIER_MULTIPLIER: dict[int, float] = {1: 1.0, 2: 0.85, 3: 0.7, 4: 0.55}


def impact_weight(business_criticality: BusinessCriticality, tier: int | None) -> float:
    base = BUSINESS_CRITICALITY_WEIGHT[business_criticality]
    if tier is None:
        return base
    return base * TIER_MULTIPLIER.get(tier, 1.0)


def statement_density(gap: TechniqueGapAnalysis) -> float:
    if gap.cri_mapping_absent or not gap.cri_in_tier_statement_ids:
        return 0.0
    return len(gap.cri_gap_statement_ids) / len(gap.cri_in_tier_statement_ids)


def _resolve_regulatory_exposure(
    gap_statement_ids: set[str],
    statements_by_id: dict[str, DiagnosticStatement],
    regulatory_documents: dict[str, dict],
) -> tuple[RegulatoryExposure, ...]:
    exposures: dict[str, RegulatoryExposure] = {}
    for statement_id in gap_statement_ids:
        statement = statements_by_id.get(statement_id)
        if statement is None:
            continue
        for ref in statement.regulatory_references:
            doc = regulatory_documents.get(ref.short_code)
            if doc is None:
                continue
            exposures[ref.short_code] = RegulatoryExposure(
                short_code=ref.short_code,
                document_name=doc["document_name"],
                issuing_organization=doc["issuing_organization"],
            )
    return tuple(sorted(exposures.values(), key=lambda e: e.short_code))


def score_path(
    path: AttackPath,
    gaps_by_technique: dict[str, TechniqueGapAnalysis],
    business_criticality: BusinessCriticality,
    tier: int | None,
    statements_by_id: dict[str, DiagnosticStatement],
    regulatory_documents: dict[str, dict],
) -> RiskFinding:
    technique_ids = tuple(dict.fromkeys(step.technique_id for step in path.steps))
    relevant_gaps = [gaps_by_technique[t] for t in technique_ids if t in gaps_by_technique]

    densities = [statement_density(g) for g in relevant_gaps if not g.cri_mapping_absent]
    density = max(densities) if densities else 0.0

    d3fend_gap_ids = {gid for g in relevant_gaps for gid in g.d3fend_gap_ids}
    cri_gap_ids = {gid for g in relevant_gaps for gid in g.cri_gap_statement_ids}
    cri_mapping_absent = all(g.cri_mapping_absent for g in relevant_gaps) if relevant_gaps else True

    weight = impact_weight(business_criticality, tier)
    score = path.aggregate_likelihood * weight * (1 + density)

    csf_functions = tuple(
        sorted({csf_function_code(sid) for g in relevant_gaps for sid in g.cri_in_tier_statement_ids})
    )
    regulatory_exposure = _resolve_regulatory_exposure(
        cri_gap_ids, statements_by_id, regulatory_documents
    )

    return RiskFinding(
        path_id=path.id,
        entry_point=path.entry_point,
        target=path.target,
        technique_ids=technique_ids,
        tactic_sequence=path.tactic_sequence,
        score=score,
        factors=RiskFactors(
            likelihood=path.aggregate_likelihood,
            impact_weight=weight,
            statement_density=density,
            d3fend_gap_count=len(d3fend_gap_ids),
            cri_gap_count=len(cri_gap_ids),
            cri_mapping_absent=cri_mapping_absent,
        ),
        csf_functions=csf_functions,
        regulatory_exposure=regulatory_exposure,
    )
