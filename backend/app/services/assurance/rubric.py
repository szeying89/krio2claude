"""Task 20's confidence rubric (Assurance Agent, Q4): six pure-function
dimensions over already-computed run artifacts, each independently
testable, aggregated with fixed, documented, equal weights into a 0-100
score and band. No clock, no network, no LLM call anywhere in this
module — recomputing from the same artifacts always reproduces the same
report, and none of these six dimensions read anything Task 19's intel
pipeline produces, so attaching intel never moves this score on its own
(only a genuine change to the underlying model/enumeration/gaps/
assumptions would).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.adjudication import Adjudication
from app.services.enumeration.agent import RejectionLogEntry
from app.services.enumeration.matrix import EnumerationResult
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.modelbuilding.models import Assumption
from app.services.systemmodel.models import SystemModel

DIMENSION_WEIGHT = 1.0 / 6

BAND_HIGH_THRESHOLD = 80.0
BAND_MODERATE_THRESHOLD = 50.0


@dataclass(frozen=True)
class RubricDimension:
    name: str
    score: float  # 0-100
    weight: float
    raw_counts: dict[str, int]
    detail: str


@dataclass(frozen=True)
class ConfidenceReport:
    dimensions: tuple[RubricDimension, ...]
    overall_score: float
    band: str


def _band(score: float) -> str:
    if score >= BAND_HIGH_THRESHOLD:
        return "High"
    if score >= BAND_MODERATE_THRESHOLD:
        return "Moderate"
    return "Low"


def element_coverage(model: SystemModel, enumeration_result: EnumerationResult) -> RubricDimension:
    """Fraction of in-scope components that were actually analyzed — i.e.
    matched at least one STRIDE or LINDDUN rule and so appear in the
    matrix with a non-empty category list, rather than being silently
    skipped because nothing in the ruleset recognized their kind/tags."""
    in_scope_ids = {c.id for c in model.components if not c.out_of_scope}
    rows_by_element = {row.element_id: row for row in enumeration_result.matrix}

    covered = 0
    for element_id in in_scope_ids:
        row = rows_by_element.get(element_id)
        if row is not None and (row.stride_categories or row.linddun_categories):
            covered += 1

    total = len(in_scope_ids)
    score = 100.0 * covered / total if total else 100.0
    return RubricDimension(
        name="element_coverage",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"covered": covered, "total_in_scope": total},
        detail=f"{covered} of {total} in-scope element(s) matched at least one STRIDE/LINDDUN rule",
    )


def cell_adjudication_rate(
    candidate_count: int, adjudicated_threats: list[Adjudication], rejection_log: list[RejectionLogEntry]
) -> RubricDimension:
    """Fraction of enumerated STRIDE/LINDDUN candidates that reached a
    final applicable/not_applicable verdict rather than being rejected
    for failing grounding."""
    adjudicated = len(adjudicated_threats)
    rejected = len(rejection_log)
    total = adjudicated + rejected
    score = 100.0 * adjudicated / total if total else 100.0
    return RubricDimension(
        name="cell_adjudication_rate",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"adjudicated": adjudicated, "rejected": rejected, "candidate_count": candidate_count},
        detail=f"{adjudicated} of {total} enumerated candidate(s) reached a final adjudication verdict",
    )


def grounding_rate(adjudicated_threats: list[Adjudication]) -> RubricDimension:
    """Mean citation strength among adjudicated candidates — distinct
    from `cell_adjudication_rate`'s pass/fail count: this measures *how
    strong* the surviving evidence is, not merely whether a verdict was
    reached at all."""
    if not adjudicated_threats:
        return RubricDimension(
            name="grounding_rate",
            score=100.0,
            weight=DIMENSION_WEIGHT,
            raw_counts={"adjudicated_count": 0},
            detail="no adjudicated candidates to measure",
        )
    mean_citation = sum(a.citation_score for a in adjudicated_threats) / len(adjudicated_threats)
    score = 100.0 * min(mean_citation, 1.0)
    return RubricDimension(
        name="grounding_rate",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"adjudicated_count": len(adjudicated_threats)},
        detail=f"mean citation score {mean_citation:.3f} across {len(adjudicated_threats)} adjudicated candidate(s)",
    )


def cri_mapping_completeness(gaps: list[TechniqueGapAnalysis]) -> RubricDimension:
    """Real vs inferred-fallback vs fully-absent CRI mapping, per Task
    15's own three-way distinction — only "real" mappings count toward
    the score; an inferred fallback is a hint for a human, not evidence
    of real coverage."""
    real = sum(1 for g in gaps if not g.cri_mapping_absent)
    inferred_fallback = sum(
        1 for g in gaps if g.cri_mapping_absent and g.cri_mapping_inferred_fallback_ids
    )
    absent = sum(1 for g in gaps if g.cri_mapping_absent and not g.cri_mapping_inferred_fallback_ids)
    total = len(gaps)
    score = 100.0 * real / total if total else 100.0
    return RubricDimension(
        name="cri_mapping_completeness",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"real": real, "inferred_fallback": inferred_fallback, "absent": absent},
        detail=f"{real} of {total} technique(s) have a real CRI mapping "
        f"({inferred_fallback} inferred-fallback only, {absent} fully absent)",
    )


def unresolved_assumptions(assumptions: list[Assumption]) -> RubricDimension:
    """Mean confidence across the assumption ledger — an assumption the
    model-building step itself wasn't confident about is a bigger
    unresolved risk than a routine, high-confidence default."""
    if not assumptions:
        return RubricDimension(
            name="unresolved_assumptions",
            score=100.0,
            weight=DIMENSION_WEIGHT,
            raw_counts={"count": 0},
            detail="no assumptions were made",
        )
    mean_confidence = sum(a.confidence for a in assumptions) / len(assumptions)
    score = 100.0 * min(mean_confidence, 1.0)
    return RubricDimension(
        name="unresolved_assumptions",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"count": len(assumptions)},
        detail=f"{len(assumptions)} assumption(s), mean confidence {mean_confidence:.3f}",
    )


def limitations_completeness(model: SystemModel) -> RubricDimension:
    """Every component flagged out-of-scope must have a corresponding
    `OutOfScopeDeclaration` (with its own real reason, by construction of
    Task 9's detector) — this catches an unexplained exclusion: a
    component marked out-of-scope with no declaration recorded for it."""
    declared_subject_ids = {d.subject_id for d in model.out_of_scope}
    out_of_scope_component_ids = {c.id for c in model.components if c.out_of_scope}

    explained = sum(1 for cid in out_of_scope_component_ids if cid in declared_subject_ids)
    total = len(out_of_scope_component_ids)
    score = 100.0 * explained / total if total else 100.0
    return RubricDimension(
        name="limitations_completeness",
        score=score,
        weight=DIMENSION_WEIGHT,
        raw_counts={"explained": explained, "total_out_of_scope": total},
        detail=f"{explained} of {total} out-of-scope component(s) have a recorded declaration",
    )


def compute_coverage_report(
    model: SystemModel,
    enumeration_result: EnumerationResult,
    candidate_count: int,
    adjudicated_threats: list[Adjudication],
    rejection_log: list[RejectionLogEntry],
    gaps: list[TechniqueGapAnalysis],
    assumptions: list[Assumption],
) -> ConfidenceReport:
    dimensions = (
        element_coverage(model, enumeration_result),
        cell_adjudication_rate(candidate_count, adjudicated_threats, rejection_log),
        grounding_rate(adjudicated_threats),
        cri_mapping_completeness(gaps),
        unresolved_assumptions(assumptions),
        limitations_completeness(model),
    )
    overall_score = sum(d.score * d.weight for d in dimensions)
    return ConfidenceReport(dimensions=dimensions, overall_score=overall_score, band=_band(overall_score))
