"""Assembles a `RiskRegister` (Task 16) from Task 13's path enumeration and
Task 15's per-technique gap analysis: one `RiskFinding` per enumerated
attack path, plus a CSF-2.0-function rollup exposing control-debt
concentration across every technique in scope — independent of which
specific paths reach them, since the rollup is about statement coverage,
not path likelihood.
"""

from __future__ import annotations

from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import PathEnumerationResult
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.risk.csf import csf_function_code
from app.services.risk.models import CSFFunctionRollup, RiskRegister
from app.services.risk.scoring import score_path


def build_csf_rollup(gaps: list[TechniqueGapAnalysis]) -> tuple[CSFFunctionRollup, ...]:
    techniques_by_function: dict[str, set[str]] = {}
    in_tier_by_function: dict[str, set[str]] = {}
    gap_by_function: dict[str, set[str]] = {}

    for gap in gaps:
        for statement_id in gap.cri_in_tier_statement_ids:
            function = csf_function_code(statement_id)
            techniques_by_function.setdefault(function, set()).add(gap.technique_id)
            in_tier_by_function.setdefault(function, set()).add(statement_id)
        for statement_id in gap.cri_gap_statement_ids:
            gap_by_function.setdefault(csf_function_code(statement_id), set()).add(statement_id)

    rollup = []
    for function in sorted(in_tier_by_function):
        in_tier_count = len(in_tier_by_function[function])
        unsatisfied_count = len(gap_by_function.get(function, ()))
        rollup.append(
            CSFFunctionRollup(
                function=function,
                technique_count=len(techniques_by_function.get(function, ())),
                in_tier_statement_count=in_tier_count,
                unsatisfied_statement_count=unsatisfied_count,
                unsatisfied_density=unsatisfied_count / in_tier_count if in_tier_count else 0.0,
            )
        )
    return tuple(sorted(rollup, key=lambda r: r.unsatisfied_density, reverse=True))


def build_risk_register(
    path_result: PathEnumerationResult,
    gaps: list[TechniqueGapAnalysis],
    business_criticality: BusinessCriticality,
    tier: int | None,
    cri_statements: list[DiagnosticStatement],
    regulatory_documents: dict[str, dict],
) -> RiskRegister:
    gaps_by_technique = {g.technique_id: g for g in gaps}
    statements_by_id = {s.profile_id: s for s in cri_statements}

    findings = tuple(
        score_path(
            path,
            gaps_by_technique,
            business_criticality,
            tier,
            statements_by_id,
            regulatory_documents,
        )
        for path in path_result.paths
    )

    return RiskRegister(
        degraded=not cri_statements,
        tier=tier,
        findings=findings,
        csf_rollup=build_csf_rollup(gaps),
    )
