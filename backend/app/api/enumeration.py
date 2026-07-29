from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_project_service, get_system_model_service
from app.core.config import get_settings
from app.services.enumeration.atlas_detector import detect_atlas_indicators
from app.services.enumeration.bridge import (
    BridgedTechnique,
    TechniqueIndex,
    bridge_candidates,
    build_technique_index,
)
from app.services.enumeration.matrix import EnumerationResult, build_enumeration_result
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.snapshot import latest_snapshot_dir, read_techniques
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["enumeration"])

_RULESET = load_ruleset()
_technique_indexes: dict[str, TechniqueIndex] = {}


def _get_technique_index() -> TechniqueIndex | None:
    """The CAPEC bridge needs a KB snapshot's real technique corpus; if none
    has ever been fetched (Task 3), enumeration still works — it simply
    returns STRIDE/LINDDUN candidates with no bridged techniques attached,
    rather than failing the whole request over a missing, optional bridge."""
    snapshot_dir = latest_snapshot_dir(get_settings().kb_dir)
    if snapshot_dir is None:
        return None
    key = snapshot_dir.name
    if key not in _technique_indexes:
        _technique_indexes[key] = build_technique_index(read_techniques(snapshot_dir))
    return _technique_indexes[key]


class BridgedTechniqueOut(BaseModel):
    technique_id: str
    technique_name: str
    matrix: str
    capec_ids: list[str]
    fused_score: float


class CandidateThreatOut(BaseModel):
    id: str
    element_id: str
    element_kind: str
    framework: str
    category: str
    ruleset_version: str
    bridged_techniques: list[BridgedTechniqueOut] = []


class ElementMatrixRowOut(BaseModel):
    element_id: str
    element_name: str
    element_kind: str
    stride_categories: list[str]
    linddun_categories: list[str]


class EnumerationResultOut(BaseModel):
    ruleset_version: str
    linddun_present: bool
    atlas_enabled: bool
    matrix: list[ElementMatrixRowOut]
    candidates: list[CandidateThreatOut]


def _bridged_out(techniques: list[BridgedTechnique]) -> list[BridgedTechniqueOut]:
    return [
        BridgedTechniqueOut(
            technique_id=t.technique_id,
            technique_name=t.technique_name,
            matrix=t.matrix,
            capec_ids=list(t.capec_ids),
            fused_score=t.fused_score,
        )
        for t in techniques
    ]


def _result_out(
    model: SystemModel, result: EnumerationResult, atlas_enabled: bool
) -> EnumerationResultOut:
    index = _get_technique_index()
    allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)
    bridged_by_candidate = (
        bridge_candidates(model, list(result.candidates), index, allowed_matrices=allowed_matrices)
        if index is not None
        else {}
    )

    return EnumerationResultOut(
        ruleset_version=result.ruleset_version,
        linddun_present=result.linddun_present,
        atlas_enabled=atlas_enabled,
        matrix=[
            ElementMatrixRowOut(
                element_id=row.element_id,
                element_name=row.element_name,
                element_kind=row.element_kind,
                stride_categories=list(row.stride_categories),
                linddun_categories=list(row.linddun_categories),
            )
            for row in result.matrix
        ],
        candidates=[
            CandidateThreatOut(
                id=c.id,
                element_id=c.element_id,
                element_kind=c.element_kind,
                framework=c.framework,
                category=c.category,
                ruleset_version=c.ruleset_version,
                bridged_techniques=_bridged_out(bridged_by_candidate.get(c.id, [])),
            )
            for c in result.candidates
        ],
    )


@router.get("/{project_id}/system-model/threats", response_model=EnumerationResultOut)
async def get_latest_enumeration(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> EnumerationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return _result_out(model, build_enumeration_result(model, _RULESET), project.atlas_enabled)


@router.get(
    "/{project_id}/system-model/versions/{version}/threats", response_model=EnumerationResultOut
)
async def get_enumeration_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> EnumerationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    return _result_out(model, build_enumeration_result(model, _RULESET), project.atlas_enabled)


class AtlasIndicatorFindingOut(BaseModel):
    subject_id: str
    category: str
    indicator: str


class AtlasProposalOut(BaseModel):
    atlas_enabled: bool
    proposed: bool
    findings: list[AtlasIndicatorFindingOut]


@router.get("/{project_id}/atlas-proposal", response_model=AtlasProposalOut)
async def get_atlas_proposal(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AtlasProposalOut:
    """Runs the deterministic ML-indicator detector against the latest
    frozen model and reports what it found — this call has zero side
    effects. ATLAS is never enabled here; see atlas-confirmation."""
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc

    findings = detect_atlas_indicators(model.components)
    return AtlasProposalOut(
        atlas_enabled=project.atlas_enabled,
        proposed=len(findings) > 0,
        findings=[
            AtlasIndicatorFindingOut(subject_id=f.subject_id, category=f.category, indicator=f.indicator)
            for f in findings
        ],
    )


class AtlasConfirmationIn(BaseModel):
    enabled: bool


class AtlasConfirmationOut(BaseModel):
    atlas_enabled: bool


@router.post("/{project_id}/atlas-confirmation", response_model=AtlasConfirmationOut)
async def confirm_atlas(
    project_id: str,
    body: AtlasConfirmationIn,
    project_service: ProjectService = Depends(get_project_service),
) -> AtlasConfirmationOut:
    """The only path that can change whether ATLAS affects enumeration —
    an explicit user action, never a side effect of the detector running."""
    try:
        project = await project_service.update_project(project_id, atlas_enabled=body.enabled)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return AtlasConfirmationOut(atlas_enabled=project.atlas_enabled)
