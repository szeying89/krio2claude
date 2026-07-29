from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_project_cri_service, get_project_service, get_system_model_service
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.services.cri.db_service import ProjectCRIService
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
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


async def _build_control_gaps(
    project_id: str,
    model: SystemModel,
    atlas_enabled: bool,
    cri_service: ProjectCRIService,
) -> ControlGapsOut:
    cri_statements = await cri_statements_with_bridge(cri_service, project_id)
    tiering = await cri_service.get_tiering(project_id)
    tier = tiering.tier if tiering is not None else None

    snapshot = get_kb_snapshot()
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
