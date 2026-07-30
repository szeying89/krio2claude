"""Risk register data model (Task 16)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RegulatoryExposure:
    short_code: str
    document_name: str
    issuing_organization: str


@dataclass(frozen=True)
class RiskFactors:
    likelihood: float
    impact_weight: float
    statement_density: float
    d3fend_gap_count: int
    cri_gap_count: int
    cri_mapping_absent: bool


@dataclass(frozen=True)
class RiskFinding:
    path_id: str
    entry_point: str
    target: str
    technique_ids: tuple[str, ...]
    tactic_sequence: tuple[str, ...]
    score: float
    factors: RiskFactors
    csf_functions: tuple[str, ...]
    regulatory_exposure: tuple[RegulatoryExposure, ...]


@dataclass(frozen=True)
class CSFFunctionRollup:
    function: str
    technique_count: int
    in_tier_statement_count: int
    unsatisfied_statement_count: int
    unsatisfied_density: float


@dataclass(frozen=True)
class RiskRegister:
    degraded: bool
    tier: int | None
    findings: tuple[RiskFinding, ...]
    csf_rollup: tuple[CSFFunctionRollup, ...]
