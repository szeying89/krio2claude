from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import (
    get_llm_gateway,
    get_project_cri_service,
    get_project_service,
    get_system_model_service,
)
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.rubric import ConfidenceReport, compute_coverage_report
from app.services.cri.db_service import ProjectCRIService
from app.services.enumeration.agent import (
    AGENT_NAME as ENUMERATION_AGENT_NAME,
)
from app.services.enumeration.agent import build_enumeration_agent, validate_enumeration_grounding
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.matrix import build_enumeration_result
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.gap_analysis import compute_technique_gaps, techniques_in_paths
from app.services.mitigation.inventory import build_control_inventory
from app.services.modelbuilding.agent import documents_input_for_project, run_model_building
from app.services.project_service import Project, ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["assurance"])

_RULESET = load_ruleset()


class RubricDimensionOut(BaseModel):
    name: str
    score: float
    weight: float
    raw_counts: dict[str, int]
    detail: str


class ConfidenceReportOut(BaseModel):
    dimensions: list[RubricDimensionOut]
    overall_score: float
    band: str


def _report_out(report: ConfidenceReport) -> ConfidenceReportOut:
    return ConfidenceReportOut(
        dimensions=[
            RubricDimensionOut(
                name=d.name, score=d.score, weight=d.weight, raw_counts=d.raw_counts, detail=d.detail
            )
            for d in report.dimensions
        ],
        overall_score=report.overall_score,
        band=report.band,
    )


async def _compute_confidence(
    project: Project,
    model: SystemModel,
    cri_service: ProjectCRIService,
    gateway: LLMGateway,
) -> ConfidenceReportOut:
    enumeration_result = build_enumeration_result(model, _RULESET)

    snapshot = get_kb_snapshot()
    index = snapshot.index if snapshot is not None else None

    registry = AgentRegistry()
    registry.register(build_enumeration_agent(_RULESET, index))
    orchestrator = Orchestrator(registry, validate=validate_enumeration_grounding)
    enum_result = orchestrator.invoke(
        ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": project.atlas_enabled}
    )
    adjudicated_threats = enum_result.output_artifacts["adjudicated_threats"]
    rejection_log = enum_result.output_artifacts["rejection_log"]
    candidate_count = enum_result.output_artifacts["candidate_count"]

    gaps: list = []
    if snapshot is not None:
        cri_statements = await cri_statements_with_bridge(cri_service, project.id)
        tiering = await cri_service.get_tiering(project.id)
        tier = tiering.tier if tiering is not None else None

        allowed_matrices = ("enterprise", "atlas") if project.atlas_enabled else ("enterprise",)
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
        inventory = build_control_inventory(model.declared_controls, snapshot.d3fend_catalog, cri_statements)
        gaps = compute_technique_gaps(
            technique_ids, snapshot.techniques_by_id, inventory, cri_statements, tier
        )

    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)
    documents = documents_input_for_project(project)
    draft = run_model_building(gateway, params, documents)

    report = compute_coverage_report(
        model=model,
        enumeration_result=enumeration_result,
        candidate_count=candidate_count,
        adjudicated_threats=adjudicated_threats,
        rejection_log=rejection_log,
        gaps=gaps,
        assumptions=draft.assumptions,
    )
    return _report_out(report)


@router.get("/{project_id}/system-model/confidence", response_model=ConfidenceReportOut)
async def get_latest_confidence(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> ConfidenceReportOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return await _compute_confidence(project, model, cri_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central grounding gate rejected agent output: {exc}"
        ) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/confidence", response_model=ConfidenceReportOut
)
async def get_confidence_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> ConfidenceReportOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return await _compute_confidence(project, model, cri_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central grounding gate rejected agent output: {exc}"
        ) from exc
