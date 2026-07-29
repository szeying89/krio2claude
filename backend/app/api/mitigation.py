from dataclasses import replace

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_project_cri_service, get_project_service, get_system_model_service
from app.core.config import get_settings
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.bridge import TechniqueIndex, build_technique_index
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import latest_snapshot_dir, read_d3fend_catalog, read_techniques
from app.services.mitigation.gap_analysis import compute_technique_gaps, techniques_in_paths
from app.services.mitigation.inventory import build_control_inventory
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["mitigation"])

_RULESET = load_ruleset()
_technique_indexes: dict[str, TechniqueIndex] = {}


class _KbSnapshot:
    def __init__(
        self,
        index: TechniqueIndex,
        techniques_by_id: dict[str, TechniqueChunk],
        d3fend_catalog: list[D3fendTechnique],
    ) -> None:
        self.index = index
        self.techniques_by_id = techniques_by_id
        self.d3fend_catalog = d3fend_catalog


def _get_kb_snapshot() -> _KbSnapshot | None:
    """The gap analysis needs the live KB technique corpus (both as a
    bridge index, to drive `techniques_in_paths` via attack-graph
    construction, and as a plain by-id lookup for each technique's own
    D3FEND requirements) plus the D3FEND catalog snapshotted alongside it.
    If no KB has ever been fetched (Task 3), gap analysis has nothing to
    compute requirements against — this returns None rather than failing
    the whole request over a missing, optional prerequisite."""
    snapshot_dir = latest_snapshot_dir(get_settings().kb_dir)
    if snapshot_dir is None:
        return None
    key = snapshot_dir.name
    if key not in _technique_indexes:
        _technique_indexes[key] = build_technique_index(read_techniques(snapshot_dir))
    techniques_by_id = {c.id: c for c in read_techniques(snapshot_dir)}
    d3fend_catalog = read_d3fend_catalog(snapshot_dir)
    return _KbSnapshot(_technique_indexes[key], techniques_by_id, d3fend_catalog)


class ControlInventoryEntryOut(BaseModel):
    control_id: str
    control_name: str
    d3fend_ids: list[str]
    cri_statement_ids: list[str]


class TechniqueGapOut(BaseModel):
    technique_id: str
    d3fend_required_ids: list[str]
    d3fend_observed_ids: list[str]
    d3fend_gap_ids: list[str]
    cri_mapping_absent: bool
    cri_in_tier_statement_ids: list[str]
    cri_gap_statement_ids: list[str]
    cri_mapping_inferred_fallback_ids: list[str]


class ControlGapsOut(BaseModel):
    tier: int | None
    control_inventory: list[ControlInventoryEntryOut]
    technique_gaps: list[TechniqueGapOut]


async def _cri_statements(
    cri_service: ProjectCRIService, project_id: str
) -> list[DiagnosticStatement]:
    """Degrades gracefully when no CRI profile has been uploaded yet — the
    project's technique gaps then simply report every technique as
    `cri_mapping_absent`, the same "degrade, don't fail" pattern used
    elsewhere in this plan, rather than 404ing the whole endpoint over an
    optional input.

    `get_statements` returns statements straight from the workbook parse,
    where `mapped_technique_ids` is always empty (Task 4's heuristic
    CRI->ATT&CK bridge is stored separately, as `inferred_mappings.json`,
    keyed by a specific KB pin — see cri/snapshot.py). Merge that bridge in
    here so `compute_technique_gaps` sees the real inferred mapping rather
    than treating every statement as unmapped.
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


async def _build_control_gaps(
    project_id: str,
    model: SystemModel,
    atlas_enabled: bool,
    cri_service: ProjectCRIService,
) -> ControlGapsOut:
    cri_statements = await _cri_statements(cri_service, project_id)
    tiering = await cri_service.get_tiering(project_id)
    tier = tiering.tier if tiering is not None else None

    snapshot = _get_kb_snapshot()
    if snapshot is None:
        return ControlGapsOut(tier=tier, control_inventory=[], technique_gaps=[])

    allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)
    dataflow_candidates = [
        c
        for c in enumerate_threats(model, _RULESET)
        if c.element_kind == "dataflow" and c.framework == "stride"
    ]
    graph = build_attack_graph(
        model, dataflow_candidates, snapshot.index, allowed_matrices=allowed_matrices
    )
    path_result = enumerate_paths(graph, model)
    technique_ids = techniques_in_paths(path_result)

    inventory = build_control_inventory(
        model.declared_controls, snapshot.d3fend_catalog, cri_statements
    )
    gaps = compute_technique_gaps(
        technique_ids, snapshot.techniques_by_id, inventory, cri_statements, tier
    )

    return ControlGapsOut(
        tier=tier,
        control_inventory=[
            ControlInventoryEntryOut(
                control_id=e.control_id,
                control_name=e.control_name,
                d3fend_ids=list(e.d3fend_ids),
                cri_statement_ids=list(e.cri_statement_ids),
            )
            for e in inventory
        ],
        technique_gaps=[
            TechniqueGapOut(
                technique_id=g.technique_id,
                d3fend_required_ids=list(g.d3fend_required_ids),
                d3fend_observed_ids=list(g.d3fend_observed_ids),
                d3fend_gap_ids=list(g.d3fend_gap_ids),
                cri_mapping_absent=g.cri_mapping_absent,
                cri_in_tier_statement_ids=list(g.cri_in_tier_statement_ids),
                cri_gap_statement_ids=list(g.cri_gap_statement_ids),
                cri_mapping_inferred_fallback_ids=list(g.cri_mapping_inferred_fallback_ids),
            )
            for g in gaps
        ],
    )


@router.get("/{project_id}/system-model/control-gaps", response_model=ControlGapsOut)
async def get_latest_control_gaps(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
) -> ControlGapsOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return await _build_control_gaps(project_id, model, project.atlas_enabled, cri_service)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/control-gaps", response_model=ControlGapsOut
)
async def get_control_gaps_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
) -> ControlGapsOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return await _build_control_gaps(project_id, model, project.atlas_enabled, cri_service)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
