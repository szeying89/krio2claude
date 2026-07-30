"""Task 19's revision snapshot: a flat, JSON-round-trippable *summary* of
a computed threat-model state, persisted for diffing and display — not a
full replay-capable object graph. Nothing in this task needs to
reconstruct live `AttackPath`/`Adjudication`/`RiskRegister` objects from
a stored revision; re-computing from scratch against the same pinned
inputs (system model version, KB/CRI snapshot hashes, intel articles) is
already fully deterministic, so a summary is all persistence needs to
carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PathSummary:
    id: str
    entry_point: str
    target: str
    technique_ids: tuple[str, ...]
    aggregate_likelihood: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entry_point": self.entry_point,
            "target": self.target,
            "technique_ids": list(self.technique_ids),
            "aggregate_likelihood": self.aggregate_likelihood,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> PathSummary:
        return PathSummary(
            id=data["id"],
            entry_point=data["entry_point"],
            target=data["target"],
            technique_ids=tuple(data["technique_ids"]),
            aggregate_likelihood=data["aggregate_likelihood"],
        )


@dataclass(frozen=True)
class AdjudicationSummary:
    candidate_threat_id: str
    verdict: str
    citation_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_threat_id": self.candidate_threat_id,
            "verdict": self.verdict,
            "citation_score": self.citation_score,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AdjudicationSummary:
        return AdjudicationSummary(
            candidate_threat_id=data["candidate_threat_id"],
            verdict=data["verdict"],
            citation_score=data["citation_score"],
        )


@dataclass(frozen=True)
class CSFFunctionSummary:
    function: str
    unsatisfied_density: float

    def to_dict(self) -> dict[str, Any]:
        return {"function": self.function, "unsatisfied_density": self.unsatisfied_density}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> CSFFunctionSummary:
        return CSFFunctionSummary(function=data["function"], unsatisfied_density=data["unsatisfied_density"])


@dataclass(frozen=True)
class ThreatLandscapeCurrency:
    """How fresh the evidence behind this revision is — real, computable
    facts (fetch timestamps, intel article count), never a fabricated
    "freshness score.\""""

    kb_fetched_at: str | None
    cri_fetched_at: str | None
    intel_article_count: int
    latest_intel_fetched_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kb_fetched_at": self.kb_fetched_at,
            "cri_fetched_at": self.cri_fetched_at,
            "intel_article_count": self.intel_article_count,
            "latest_intel_fetched_at": self.latest_intel_fetched_at,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ThreatLandscapeCurrency:
        return ThreatLandscapeCurrency(
            kb_fetched_at=data.get("kb_fetched_at"),
            cri_fetched_at=data.get("cri_fetched_at"),
            intel_article_count=data.get("intel_article_count", 0),
            latest_intel_fetched_at=data.get("latest_intel_fetched_at"),
        )


@dataclass(frozen=True)
class RevisionSnapshot:
    paths: tuple[PathSummary, ...]
    adjudications: tuple[AdjudicationSummary, ...]
    rejection_count: int
    risk_total_score: float
    csf_rollup: tuple[CSFFunctionSummary, ...]
    confidence: float
    currency: ThreatLandscapeCurrency

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": [p.to_dict() for p in self.paths],
            "adjudications": [a.to_dict() for a in self.adjudications],
            "rejection_count": self.rejection_count,
            "risk_total_score": self.risk_total_score,
            "csf_rollup": [c.to_dict() for c in self.csf_rollup],
            "confidence": self.confidence,
            "currency": self.currency.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> RevisionSnapshot:
        return RevisionSnapshot(
            paths=tuple(PathSummary.from_dict(p) for p in data["paths"]),
            adjudications=tuple(AdjudicationSummary.from_dict(a) for a in data["adjudications"]),
            rejection_count=data["rejection_count"],
            risk_total_score=data["risk_total_score"],
            csf_rollup=tuple(CSFFunctionSummary.from_dict(c) for c in data["csf_rollup"]),
            confidence=data["confidence"],
            currency=ThreatLandscapeCurrency.from_dict(data["currency"]),
        )


@dataclass(frozen=True)
class PathLikelihoodChange:
    path_id: str
    previous_likelihood: float
    new_likelihood: float

    @property
    def delta(self) -> float:
        return self.new_likelihood - self.previous_likelihood


@dataclass(frozen=True)
class CSFMovement:
    function: str
    previous_density: float
    new_density: float

    @property
    def delta(self) -> float:
        return self.new_density - self.previous_density


@dataclass(frozen=True)
class RevisionDiff:
    new_path_ids: tuple[str, ...]
    removed_path_ids: tuple[str, ...]
    changed_paths: tuple[PathLikelihoodChange, ...]
    reopened_adjudication_ids: tuple[str, ...]
    risk_score_delta: float
    csf_rollup_movement: tuple[CSFMovement, ...]
    confidence_delta: float
