from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_llm_gateway, get_project_service, get_system_model_service
from app.core.config import get_settings
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.edits import (
    AssetEdit,
    ComponentEdit,
    DataflowEdit,
    TrustZoneEdit,
    UnknownElementError,
)
from app.services.systemmodel.edits import ModelEdits as DomainModelEdits
from app.services.systemmodel.mermaid_render import render_system_model
from app.services.systemmodel.models import SystemModel
from app.services.systemmodel.otm import to_otm

router = APIRouter(prefix="/projects", tags=["systemmodel"])


class TrustZoneOut(BaseModel):
    id: str
    name: str
    trust_rating: int
    description: str | None
    provenance: str


class ComponentOut(BaseModel):
    id: str
    name: str
    kind: str
    trust_zone_id: str
    technology_tags: list[str]
    description: str | None
    provenance: str
    out_of_scope: bool
    out_of_scope_reason: str | None


class DataflowOut(BaseModel):
    id: str
    name: str
    source_id: str
    destination_id: str
    bidirectional: bool
    protocol: str | None
    authenticated: bool | None
    encrypted: bool | None
    provenance: str


class AssetOut(BaseModel):
    id: str
    name: str
    classification: str | None
    confidentiality: int
    integrity: int
    availability: int
    owner_id: str | None
    provenance: str


class OutOfScopeOut(BaseModel):
    id: str
    subject_id: str
    category: str
    indicator: str
    reason: str


class SystemModelOut(BaseModel):
    id: str
    version: int
    parent_version: int | None
    trust_zones: list[TrustZoneOut]
    components: list[ComponentOut]
    dataflows: list[DataflowOut]
    assets: list[AssetOut]
    out_of_scope: list[OutOfScopeOut]
    change_summary: list[str]


def _model_out(model: SystemModel) -> SystemModelOut:
    return SystemModelOut(
        id=model.id,
        version=model.version,
        parent_version=model.parent_version,
        trust_zones=[
            TrustZoneOut(
                id=z.id,
                name=z.name,
                trust_rating=z.trust_rating,
                description=z.description,
                provenance=z.provenance,
            )
            for z in model.trust_zones
        ],
        components=[
            ComponentOut(
                id=c.id,
                name=c.name,
                kind=c.kind,
                trust_zone_id=c.trust_zone_id,
                technology_tags=list(c.technology_tags),
                description=c.description,
                provenance=c.provenance,
                out_of_scope=c.out_of_scope,
                out_of_scope_reason=c.out_of_scope_reason,
            )
            for c in model.components
        ],
        dataflows=[
            DataflowOut(
                id=f.id,
                name=f.name,
                source_id=f.source_id,
                destination_id=f.destination_id,
                bidirectional=f.bidirectional,
                protocol=f.protocol,
                authenticated=f.authenticated,
                encrypted=f.encrypted,
                provenance=f.provenance,
            )
            for f in model.dataflows
        ],
        assets=[
            AssetOut(
                id=a.id,
                name=a.name,
                classification=a.classification,
                confidentiality=a.confidentiality,
                integrity=a.integrity,
                availability=a.availability,
                owner_id=a.owner_id,
                provenance=a.provenance,
            )
            for a in model.assets
        ],
        out_of_scope=[
            OutOfScopeOut(
                id=o.id, subject_id=o.subject_id, category=o.category, indicator=o.indicator, reason=o.reason
            )
            for o in model.out_of_scope
        ],
        change_summary=list(model.change_summary),
    )


@router.post("/{project_id}/system-model", response_model=SystemModelOut)
async def freeze_system_model(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> SystemModelOut:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc

    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)
    model = await model_service.freeze(project_id, gateway, params)
    return _model_out(model)


@router.get("/{project_id}/system-model", response_model=SystemModelOut)
async def get_latest_system_model(
    project_id: str, model_service: ProjectSystemModelService = Depends(get_system_model_service)
) -> SystemModelOut:
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return _model_out(model)


@router.get("/{project_id}/system-model/versions", response_model=list[int])
async def list_system_model_versions(
    project_id: str, model_service: ProjectSystemModelService = Depends(get_system_model_service)
) -> list[int]:
    return await model_service.list_versions(project_id)


@router.get("/{project_id}/system-model/versions/{version}", response_model=SystemModelOut)
async def get_system_model_version(
    project_id: str,
    version: int,
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> SystemModelOut:
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    return _model_out(model)


class ModelEditsIn(BaseModel):
    components: list[ComponentEdit] = []
    dataflows: list[DataflowEdit] = []
    assets: list[AssetEdit] = []
    trust_zones: list[TrustZoneEdit] = []


@router.patch("/{project_id}/system-model", response_model=SystemModelOut)
async def edit_system_model(
    project_id: str,
    body: ModelEditsIn,
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> SystemModelOut:
    edits = DomainModelEdits(
        components=body.components,
        dataflows=body.dataflows,
        assets=body.assets,
        trust_zones=body.trust_zones,
    )
    try:
        model = await model_service.apply_user_edits(project_id, edits)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    except UnknownElementError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _model_out(model)


@router.get("/{project_id}/system-model/otm")
async def export_otm(
    project_id: str, model_service: ProjectSystemModelService = Depends(get_system_model_service)
) -> dict[str, Any]:
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return to_otm(model)


class MermaidOut(BaseModel):
    source: str


@router.get("/{project_id}/system-model/mermaid", response_model=MermaidOut)
async def render_mermaid(
    project_id: str, model_service: ProjectSystemModelService = Depends(get_system_model_service)
) -> MermaidOut:
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return MermaidOut(source=render_system_model(model))
