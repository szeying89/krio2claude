"""Per-element STRIDE/LINDDUN matrix view for display — the same
candidates `enumerate_threats` produces, grouped by element instead of
flattened, plus the summary counts a UI needs (per the plan's demo:
"per-element candidate counts and a LINDDUN section appearing only when
personal data is present")."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.enumeration.engine import CandidateThreat, enumerate_threats
from app.services.enumeration.ruleset import Ruleset
from app.services.systemmodel.models import SystemModel


@dataclass(frozen=True)
class ElementMatrixRow:
    element_id: str
    element_name: str
    element_kind: str
    stride_categories: tuple[str, ...]
    linddun_categories: tuple[str, ...]


@dataclass(frozen=True)
class EnumerationResult:
    ruleset_version: str
    candidates: tuple[CandidateThreat, ...]
    matrix: tuple[ElementMatrixRow, ...] = field(default_factory=tuple)

    @property
    def linddun_present(self) -> bool:
        return any(c.framework == "linddun" for c in self.candidates)


def build_enumeration_result(model: SystemModel, ruleset: Ruleset) -> EnumerationResult:
    """The matrix always includes every component and dataflow in the
    model — including out-of-scope ones, shown with empty category tuples
    — so a "full STRIDE-per-element matrix" reads as complete, not as a
    silently-filtered subset."""
    candidates = enumerate_threats(model, ruleset)

    by_element: dict[str, list[CandidateThreat]] = {}
    for candidate in candidates:
        by_element.setdefault(candidate.element_id, []).append(candidate)

    def _row(element_id: str, name: str, kind: str) -> ElementMatrixRow:
        element_candidates = by_element.get(element_id, [])
        return ElementMatrixRow(
            element_id=element_id,
            element_name=name,
            element_kind=kind,
            stride_categories=tuple(
                c.category for c in element_candidates if c.framework == "stride"
            ),
            linddun_categories=tuple(
                c.category for c in element_candidates if c.framework == "linddun"
            ),
        )

    matrix = tuple(
        _row(c.id, c.name, c.kind) for c in model.components
    ) + tuple(_row(f.id, f.name or f.id, "dataflow") for f in model.dataflows)

    return EnumerationResult(
        ruleset_version=ruleset.version, candidates=tuple(candidates), matrix=matrix
    )
