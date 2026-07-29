"""Control inventory (Task 15): consolidates a project's declared
controls and maps each one to D3FEND countermeasure IDs and CRI
diagnostic-statement IDs — both heuristic (no authoritative "control
name -> D3FEND ID" or "control name -> CRI statement ID" source exists
anywhere in this plan's data), same lexical-overlap spirit as
`app/services/kb/heuristic_mapping.py`, whose `tokenize` this reuses
directly rather than re-implementing tokenization.

A generic matcher rather than a reuse of `infer_technique_mappings`
itself: that function's target type is hard-coded to `TechniqueChunk`
(ATT&CK techniques), and both of this task's targets are something else
(D3FEND countermeasures, CRI statements) — the tokenization logic is
identical, only the target shape differs.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.cri.models import DiagnosticStatement
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.heuristic_mapping import HeuristicSource, tokenize
from app.services.systemmodel.models import DeclaredControl

DEFAULT_MIN_SHARED_TOKENS = 2


@dataclass(frozen=True)
class ControlInventoryEntry:
    control_id: str
    control_name: str
    d3fend_ids: tuple[str, ...]
    cri_statement_ids: tuple[str, ...]


def lexical_match(
    source: HeuristicSource, targets: list[HeuristicSource], min_shared_tokens: int
) -> tuple[str, ...]:
    source_tokens = tokenize(f"{source.name} {source.text}")
    if not source_tokens:
        return ()
    matches = []
    for target in targets:
        target_tokens = tokenize(f"{target.name} {target.text}")
        if len(source_tokens & target_tokens) >= min_shared_tokens:
            matches.append(target.id)
    return tuple(sorted(matches))


def build_control_inventory(
    declared_controls: list[DeclaredControl],
    d3fend_catalog: list[D3fendTechnique],
    cri_statements: list[DiagnosticStatement],
    min_shared_tokens: int = DEFAULT_MIN_SHARED_TOKENS,
) -> list[ControlInventoryEntry]:
    d3fend_sources = [HeuristicSource(id=d.id, name=d.name, text=d.definition) for d in d3fend_catalog]
    cri_sources = [
        HeuristicSource(id=s.profile_id, name=s.name, text=s.text) for s in cri_statements
    ]

    entries = []
    for control in declared_controls:
        control_source = HeuristicSource(id=control.id, name=control.name, text="")
        entries.append(
            ControlInventoryEntry(
                control_id=control.id,
                control_name=control.name,
                d3fend_ids=lexical_match(control_source, d3fend_sources, min_shared_tokens),
                cri_statement_ids=lexical_match(control_source, cri_sources, min_shared_tokens),
            )
        )
    return entries
