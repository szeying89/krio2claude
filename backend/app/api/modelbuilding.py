from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_llm_gateway, get_project_service
from app.core.config import get_settings
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.modelbuilding.agent import documents_input_for_project, run_model_building
from app.services.modelbuilding.models import (
    Assumption,
    CompletenessFinding,
    DeclaredControl,
    ModelActor,
    ModelAsset,
    ModelComponent,
    ModelFlow,
    ModelTrustZone,
    SourceSpan,
    SystemModelDraft,
)
from app.services.project_service import ProjectNotFoundError, ProjectService

router = APIRouter(prefix="/projects", tags=["modelbuilding"])


class SourceSpanOut(BaseModel):
    document_id: str
    start_line: int
    end_line: int


class AssumptionOut(BaseModel):
    kind: str
    subject_id: str
    message: str
    source: str
    confidence: float
    impact_if_wrong: str


class CompletenessFindingOut(BaseModel):
    kind: str
    subject_id: str
    message: str


class ComponentOut(BaseModel):
    id: str
    name: str
    kind: str
    trust_zone_id: str | None
    technology_tags: list[str]
    source: str
    source_spans: list[SourceSpanOut]


class ActorOut(BaseModel):
    id: str
    name: str
    kind: str
    source: str
    source_spans: list[SourceSpanOut]


class FlowOut(BaseModel):
    id: str
    source_id: str
    target_id: str
    label: str
    protocol: str | None
    authenticated: bool | None
    encrypted: bool | None
    source: str
    source_spans: list[SourceSpanOut]


class AssetOut(BaseModel):
    id: str
    name: str
    classification: str | None
    owner_id: str | None
    source: str
    source_spans: list[SourceSpanOut]


class TrustZoneOut(BaseModel):
    id: str
    name: str
    member_ids: list[str]
    source: str
    source_spans: list[SourceSpanOut]


class DeclaredControlOut(BaseModel):
    id: str
    name: str
    applies_to_ids: list[str]
    source: str
    source_spans: list[SourceSpanOut]


class SystemModelDraftOut(BaseModel):
    components: list[ComponentOut]
    actors: list[ActorOut]
    flows: list[FlowOut]
    assets: list[AssetOut]
    trust_zones: list[TrustZoneOut]
    declared_controls: list[DeclaredControlOut]
    assumptions: list[AssumptionOut]
    completeness_findings: list[CompletenessFindingOut]
    needs_input: bool


def _spans_out(spans: tuple[SourceSpan, ...]) -> list[SourceSpanOut]:
    return [SourceSpanOut(document_id=s.document_id, start_line=s.start_line, end_line=s.end_line) for s in spans]


def _component_out(c: ModelComponent) -> ComponentOut:
    return ComponentOut(
        id=c.id,
        name=c.name,
        kind=c.kind,
        trust_zone_id=c.trust_zone_id,
        technology_tags=list(c.technology_tags),
        source=c.source,
        source_spans=_spans_out(c.source_spans),
    )


def _actor_out(a: ModelActor) -> ActorOut:
    return ActorOut(
        id=a.id, name=a.name, kind=a.kind, source=a.source, source_spans=_spans_out(a.source_spans)
    )


def _flow_out(f: ModelFlow) -> FlowOut:
    return FlowOut(
        id=f.id,
        source_id=f.source_id,
        target_id=f.target_id,
        label=f.label,
        protocol=f.protocol,
        authenticated=f.authenticated,
        encrypted=f.encrypted,
        source=f.source,
        source_spans=_spans_out(f.source_spans),
    )


def _asset_out(a: ModelAsset) -> AssetOut:
    return AssetOut(
        id=a.id,
        name=a.name,
        classification=a.classification,
        owner_id=a.owner_id,
        source=a.source,
        source_spans=_spans_out(a.source_spans),
    )


def _trust_zone_out(z: ModelTrustZone) -> TrustZoneOut:
    return TrustZoneOut(
        id=z.id,
        name=z.name,
        member_ids=list(z.member_ids),
        source=z.source,
        source_spans=_spans_out(z.source_spans),
    )


def _declared_control_out(c: DeclaredControl) -> DeclaredControlOut:
    return DeclaredControlOut(
        id=c.id,
        name=c.name,
        applies_to_ids=list(c.applies_to_ids),
        source=c.source,
        source_spans=_spans_out(c.source_spans),
    )


def _assumption_out(a: Assumption) -> AssumptionOut:
    return AssumptionOut(
        kind=a.kind,
        subject_id=a.subject_id,
        message=a.message,
        source=a.source,
        confidence=a.confidence,
        impact_if_wrong=a.impact_if_wrong,
    )


def _finding_out(f: CompletenessFinding) -> CompletenessFindingOut:
    return CompletenessFindingOut(kind=f.kind, subject_id=f.subject_id, message=f.message)


def draft_to_response(draft: SystemModelDraft) -> SystemModelDraftOut:
    return SystemModelDraftOut(
        components=[_component_out(c) for c in draft.components],
        actors=[_actor_out(a) for a in draft.actors],
        flows=[_flow_out(f) for f in draft.flows],
        assets=[_asset_out(a) for a in draft.assets],
        trust_zones=[_trust_zone_out(z) for z in draft.trust_zones],
        declared_controls=[_declared_control_out(c) for c in draft.declared_controls],
        assumptions=[_assumption_out(a) for a in draft.assumptions],
        completeness_findings=[_finding_out(f) for f in draft.completeness_findings],
        needs_input=draft.needs_input,
    )


@router.post("/{project_id}/model-draft", response_model=SystemModelDraftOut)
async def build_model_draft(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> SystemModelDraftOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc

    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)
    documents = documents_input_for_project(project)
    draft = run_model_building(gateway, params, documents)
    return draft_to_response(draft)
