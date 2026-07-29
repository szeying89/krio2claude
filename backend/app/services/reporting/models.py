"""Task 22's canonical report data — one bundle, assembled once from
every prior task's own artifacts, that all three audience views render
from. This is what makes "shared numbers agree across audiences" true
by construction rather than by discipline: there is only one
`ReportData` object, and the Executive/CISO/Technical renderers
(`render.py`) never recompute a number themselves, only format the same
fields differently.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.assurance.rubric import ConfidenceReport
from app.services.enumeration.adjudication import Adjudication
from app.services.enumeration.agent import RejectionLogEntry
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.residual_risk import ResidualRiskComparison
from app.services.mitigation.roadmap import RoadmapPhase
from app.services.modelbuilding.models import Assumption
from app.services.revision.models import ThreatLandscapeCurrency
from app.services.risk.models import CSFFunctionRollup, RiskFinding
from app.services.systemmodel.models import OutOfScopeDeclaration, SystemModel


@dataclass(frozen=True)
class ReportData:
    project_name: str
    business_criticality: str
    model: SystemModel
    confidence: ConfidenceReport
    risk_findings: tuple[RiskFinding, ...]
    csf_rollup: tuple[CSFFunctionRollup, ...]
    tier: int | None
    tier_justification: str
    gaps: tuple[TechniqueGapAnalysis, ...]
    residual_risk: ResidualRiskComparison | None
    roadmap: tuple[RoadmapPhase, ...]
    recommendations: tuple[MitigationRecommendation, ...]
    adjudicated_threats: tuple[Adjudication, ...]
    rejection_log: tuple[RejectionLogEntry, ...]
    assumptions: tuple[Assumption, ...]
    currency: ThreatLandscapeCurrency | None
    has_cri: bool

    @property
    def model_version(self) -> int:
        return self.model.version

    @property
    def out_of_scope(self) -> tuple[OutOfScopeDeclaration, ...]:
        return tuple(self.model.out_of_scope)
