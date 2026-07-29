"""Shared plumbing for the two API surfaces that need "everything the
project currently knows against its latest KB/CRI pins" — the Task 15
control-gap view (`app/api/mitigation.py`) and the Task 16 risk register
(`app/api/risk.py`). Kept here, not duplicated, once a second real
consumer needed it — the same promote-when-actually-shared rule this
plan has followed since Task 11's `latest_snapshot_dir`.

The in-memory `TechniqueIndex` cache is deliberately an API-layer concern
(keyed by KB snapshot content hash, valid for the process lifetime), not
something the services layer should own.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from app.core.config import get_settings
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.bridge import TechniqueIndex, build_technique_index
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import latest_snapshot_dir, read_d3fend_catalog, read_techniques

_technique_indexes: dict[str, TechniqueIndex] = {}


@dataclass(frozen=True)
class KbSnapshot:
    index: TechniqueIndex
    techniques_by_id: dict[str, TechniqueChunk]
    d3fend_catalog: list[D3fendTechnique]


def clear_technique_index_cache() -> None:
    """Test-only: the cache is keyed by KB snapshot content hash, but
    tests reuse the same hash-independent tmp KB dir across runs."""
    _technique_indexes.clear()


def get_kb_snapshot() -> KbSnapshot | None:
    """Gap/risk computation needs the live KB technique corpus (both as a
    bridge index, to drive attack-graph construction, and as a plain
    by-id lookup for each technique's own D3FEND requirements) plus the
    D3FEND catalog snapshotted alongside it. If no KB has ever been
    fetched (Task 3), there is nothing to compute requirements against —
    this returns None rather than failing the whole request over a
    missing, optional prerequisite."""
    snapshot_dir = latest_snapshot_dir(get_settings().kb_dir)
    if snapshot_dir is None:
        return None
    key = snapshot_dir.name
    if key not in _technique_indexes:
        _technique_indexes[key] = build_technique_index(read_techniques(snapshot_dir))
    techniques_by_id = {c.id: c for c in read_techniques(snapshot_dir)}
    d3fend_catalog = read_d3fend_catalog(snapshot_dir)
    return KbSnapshot(_technique_indexes[key], techniques_by_id, d3fend_catalog)


async def cri_statements_with_bridge(
    cri_service: ProjectCRIService, project_id: str
) -> list[DiagnosticStatement]:
    """Degrades gracefully when no CRI profile has been uploaded yet —
    callers then simply see every technique as unmapped, the same
    "degrade, don't fail" pattern used elsewhere in this plan, rather than
    404ing the whole endpoint over an optional input.

    `get_statements` returns statements straight from the workbook parse,
    where `mapped_technique_ids` is always empty (Task 4's heuristic
    CRI->ATT&CK bridge is stored separately, as `inferred_mappings.json`,
    keyed by a specific KB pin — see cri/snapshot.py). Merge that bridge in
    here so downstream gap/risk computation sees the real inferred mapping
    rather than treating every statement as unmapped.
    """
    try:
        raw_statements = await cri_service.get_statements(project_id)
    except CRIProfileNotUploadedError:
        return []
    try:
        inferred_by_statement = await cri_service.get_inferred_mappings(project_id)
    except CRIProfileNotUploadedError:
        inferred_by_statement = {}

    statements = [DiagnosticStatement.from_dict(s) for s in raw_statements]
    return [
        replace(
            statement,
            mapped_technique_ids=tuple(
                m.technique_id for m in inferred_by_statement.get(statement.profile_id, ())
            ),
        )
        for statement in statements
    ]
