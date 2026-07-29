"""Dual-track gap analysis (Task 15): for every ATT&CK technique that
appears in any enumerated attack path (Task 13), compute two independent
gap tracks against the project's control inventory —

(a) **D3FEND gap**: which D3FEND countermeasures the technique's own
    heuristic D3FEND mapping (`TechniqueChunk.relationships["d3fend_inferred"]`,
    Task 3) says are relevant, minus the ones the inventory actually
    observes covered by some declared control.
(b) **CRI gap**: which of the technique's mapped, in-tier CRI diagnostic
    statements (Task 4's heuristic CRI->ATT&CK bridge) are *not*
    satisfied by any control in the inventory.

A technique with zero CRI statements mapped to it at all — Task 4's own
heuristic bridge found nothing — is tagged `cri_mapping_absent` rather
than silently reported as "zero gaps" (which would look like full
coverage). An *optional* fallback pass — a second, independent,
lower-confidence lexical match directly between the technique's own
name/description and CRI statement text — is attempted for such
techniques and reported in its own field, never merged into the primary
gap-statement list: it's a hint for a human to investigate, not a
substitute mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import PathEnumerationResult
from app.services.kb.heuristic_mapping import HeuristicSource
from app.services.kb.models import TechniqueChunk
from app.services.mitigation.inventory import ControlInventoryEntry, lexical_match

DEFAULT_MIN_SHARED_TOKENS = 2


@dataclass(frozen=True)
class TechniqueGapAnalysis:
    technique_id: str
    d3fend_required_ids: tuple[str, ...]
    d3fend_observed_ids: tuple[str, ...]
    d3fend_gap_ids: tuple[str, ...]
    cri_mapping_absent: bool
    cri_in_tier_statement_ids: tuple[str, ...]
    cri_gap_statement_ids: tuple[str, ...]
    cri_mapping_inferred_fallback_ids: tuple[str, ...]


def techniques_in_paths(result: PathEnumerationResult) -> set[str]:
    return {step.technique_id for path in result.paths for step in path.steps}


def entities_by_technique(result: PathEnumerationResult) -> dict[str, tuple[str, ...]]:
    """Which model entities (by id) a technique's steps actually touch —
    Task 17's mitigation recommendations need this to write
    entity-specific guidance grounded in the real model, not a generic
    technique description."""
    entities: dict[str, set[str]] = {}
    for path in result.paths:
        for step in path.steps:
            entities.setdefault(step.technique_id, set()).update(
                (step.source_entity_id, step.target_entity_id)
            )
    return {technique_id: tuple(sorted(ids)) for technique_id, ids in entities.items()}


def _observed_ids(inventory: list[ControlInventoryEntry], attr: str) -> set[str]:
    ids: set[str] = set()
    for entry in inventory:
        ids.update(getattr(entry, attr))
    return ids


def compute_technique_gaps(
    technique_ids: set[str],
    kb_techniques_by_id: dict[str, TechniqueChunk],
    inventory: list[ControlInventoryEntry],
    cri_statements: list[DiagnosticStatement],
    tier: int | None,
    min_shared_tokens: int = DEFAULT_MIN_SHARED_TOKENS,
) -> list[TechniqueGapAnalysis]:
    """`tier=None` means no CRI tiering has been computed for this project
    yet — every mapped statement is treated as in scope rather than
    filtered out, the same "degrade, don't fail" pattern as Task 4's
    missing-CRI mode."""
    observed_d3fend_ids = _observed_ids(inventory, "d3fend_ids")
    observed_cri_ids = _observed_ids(inventory, "cri_statement_ids")

    cri_by_technique: dict[str, list[DiagnosticStatement]] = {}
    for statement in cri_statements:
        for technique_id in statement.mapped_technique_ids:
            cri_by_technique.setdefault(technique_id, []).append(statement)

    cri_sources = [
        HeuristicSource(id=s.profile_id, name=s.name, text=s.text) for s in cri_statements
    ]

    results: list[TechniqueGapAnalysis] = []
    for technique_id in sorted(technique_ids):
        chunk = kb_techniques_by_id.get(technique_id)
        required_d3fend = tuple(sorted(chunk.relationships.get("d3fend_inferred", ()))) if chunk else ()
        d3fend_observed = tuple(sorted(set(required_d3fend) & observed_d3fend_ids))
        d3fend_gap = tuple(sorted(set(required_d3fend) - observed_d3fend_ids))

        mapped_statements = cri_by_technique.get(technique_id, [])
        if not mapped_statements:
            fallback_ids: tuple[str, ...] = ()
            if chunk is not None:
                technique_source = HeuristicSource(id=technique_id, name=chunk.name, text=chunk.description)
                fallback_ids = lexical_match(technique_source, cri_sources, min_shared_tokens)
            results.append(
                TechniqueGapAnalysis(
                    technique_id=technique_id,
                    d3fend_required_ids=required_d3fend,
                    d3fend_observed_ids=d3fend_observed,
                    d3fend_gap_ids=d3fend_gap,
                    cri_mapping_absent=True,
                    cri_in_tier_statement_ids=(),
                    cri_gap_statement_ids=(),
                    cri_mapping_inferred_fallback_ids=fallback_ids,
                )
            )
            continue

        in_tier = [s for s in mapped_statements if tier is None or tier in s.applicable_tiers]
        in_tier_ids = tuple(sorted({s.profile_id for s in in_tier}))
        gap_ids = tuple(sorted({s.profile_id for s in in_tier if s.profile_id not in observed_cri_ids}))

        results.append(
            TechniqueGapAnalysis(
                technique_id=technique_id,
                d3fend_required_ids=required_d3fend,
                d3fend_observed_ids=d3fend_observed,
                d3fend_gap_ids=d3fend_gap,
                cri_mapping_absent=False,
                cri_in_tier_statement_ids=in_tier_ids,
                cri_gap_statement_ids=gap_ids,
                cri_mapping_inferred_fallback_ids=(),
            )
        )

    return results
