"""Assembles Task 22's canonical `ReportData` — pure, deterministic
composition of already-computed artifacts. No LLM call, no clock, no
network; the same inputs always produce the same `ReportData`.
"""

from __future__ import annotations

from app.models.project import ImpactTiering
from app.services.assurance.rubric import ConfidenceReport
from app.services.enumeration.adjudication import Adjudication
from app.services.enumeration.agent import RejectionLogEntry
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.residual_risk import ResidualRiskComparison
from app.services.mitigation.roadmap import RoadmapPhase
from app.services.modelbuilding.models import Assumption
from app.services.reporting.models import ReportData
from app.services.revision.models import ThreatLandscapeCurrency
from app.services.risk.models import CSFFunctionRollup, RiskFinding
from app.services.systemmodel.models import SystemModel


def _tier_justification(tiering: ImpactTiering | None) -> str:
    if tiering is None:
        return "Impact tier has not been computed for this project yet."
    return (
        f"Tier {tiering.tier}, determined by question {tiering.triggering_question_id!r} "
        f"of the Impact Tiering Questionnaire."
        if tiering.triggering_question_id
        else f"Tier {tiering.tier} (fallthrough — no triggering question matched)."
    )


def assemble_report_data(
    project_name: str,
    business_criticality: str,
    model: SystemModel,
    confidence: ConfidenceReport,
    risk_findings: list[RiskFinding],
    csf_rollup: list[CSFFunctionRollup],
    tiering: ImpactTiering | None,
    gaps: list[TechniqueGapAnalysis],
    residual_risk: ResidualRiskComparison | None,
    roadmap: list[RoadmapPhase],
    recommendations: list[MitigationRecommendation],
    adjudicated_threats: list[Adjudication],
    rejection_log: list[RejectionLogEntry],
    assumptions: list[Assumption],
    currency: ThreatLandscapeCurrency | None,
    has_cri: bool,
) -> ReportData:
    return ReportData(
        project_name=project_name,
        business_criticality=business_criticality,
        model=model,
        confidence=confidence,
        risk_findings=tuple(risk_findings),
        csf_rollup=tuple(csf_rollup),
        tier=tiering.tier if tiering is not None else None,
        tier_justification=_tier_justification(tiering),
        gaps=tuple(gaps),
        residual_risk=residual_risk,
        roadmap=tuple(roadmap),
        recommendations=tuple(recommendations),
        adjudicated_threats=tuple(adjudicated_threats),
        rejection_log=tuple(rejection_log),
        assumptions=tuple(assumptions),
        currency=currency,
        has_cri=has_cri,
    )
