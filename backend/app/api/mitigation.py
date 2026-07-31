from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import (
    get_llm_gateway,
    get_project_cri_service,
    get_project_service,
    get_system_model_service,
)
from app.api.rate_limit import enforce_rate_limit
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    PathEnumerationResult,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.agent import (
    AGENT_NAME as MITIGATION_AGENT_NAME,
)
from app.services.mitigation.agent import (
    build_mitigation_agent,
    validate_mitigation_grounding,
)
from app.services.mitigation.gap_analysis import (
    compute_technique_gaps,
    entities_by_technique,
    techniques_in_paths,
)
from app.services.mitigation.inventory import build_control_inventory
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.residual_risk import compute_residual_risk
from app.services.mitigation.roadmap import build_roadmap
from app.services.project_service import Project, ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["mitigation"])

_RULESET = load_ruleset()


@dataclass
class _GapContext:
    tier: int | None
    cri_statements: list[DiagnosticStatement]
    regulatory_documents: dict
    path_result: PathEnumerationResult
    gaps: list
    techniques_by_id: dict
    d3fend_by_id: dict
    has_kb_snapshot: bool


async def _regulatory_documents(cri_service: ProjectCRIService, project_id: str) -> dict:
    try:
        return await cri_service.get_regulatory_documents(project_id)
    except CRIProfileNotUploadedError:
        return {}


async def _gather_gap_context(
    project_id: str,
    model: SystemModel,
    atlas_enabled: bool,
    cri_service: ProjectCRIService,
) -> _GapContext:
    cri_statements = await cri_statements_with_bridge(cri_service, project_id)
    regulatory_documents = await _regulatory_documents(cri_service, project_id)
    tiering = await cri_service.get_tiering(project_id)
    tier = tiering.tier if tiering is not None else None

    empty_path_result = PathEnumerationResult(paths=(), capped=False)
    snapshot = get_kb_snapshot()
    if snapshot is None:
        return _GapContext(
            tier, cri_statements, regulatory_documents, empty_path_result, [], {}, {}, has_kb_snapshot=False
        )

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
    d3fend_by_id = {d.id: d for d in snapshot.d3fend_catalog}

    return _GapContext(
        tier,
        cri_statements,
        regulatory_documents,
        path_result,
        gaps,
        snapshot.techniques_by_id,
        d3fend_by_id,
        has_kb_snapshot=True,
    )


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
    ctx = await _gather_gap_context(project_id, model, atlas_enabled, cri_service)
    if not ctx.has_kb_snapshot:
        return ControlGapsOut(tier=ctx.tier, control_inventory=[], technique_gaps=[])

    inventory = build_control_inventory(model.declared_controls, list(ctx.d3fend_by_id.values()), ctx.cri_statements)

    return ControlGapsOut(
        tier=ctx.tier,
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
            for g in ctx.gaps
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


class MitigationRecommendationOut(BaseModel):
    id: str
    technique_id: str
    d3fend_id: str
    cri_statement_ids: list[str]
    guidance: str
    referenced_entity_ids: list[str]
    effort: int


class RecommendationRejectionOut(BaseModel):
    recommendation_id: str
    technique_id: str
    reason_code: str
    detail: str


class ResidualRiskOut(BaseModel):
    baseline_total_score: float
    residual_total_score: float
    risk_reduction: float


class RoadmapPhaseOut(BaseModel):
    phase_number: int
    recommendation_ids: list[str]
    cumulative_risk_reduction: float
    phase_risk_reduction: float
    diagnostic_statements_closed: list[str]
    attack_paths_closed: list[str]


class MitigationPlanOut(BaseModel):
    tier: int | None
    recommendations: list[MitigationRecommendationOut]
    rejection_log: list[RecommendationRejectionOut]
    residual_risk: ResidualRiskOut
    roadmap: list[RoadmapPhaseOut]


def _recommendation_out(rec: MitigationRecommendation) -> MitigationRecommendationOut:
    return MitigationRecommendationOut(
        id=rec.id,
        technique_id=rec.technique_id,
        d3fend_id=rec.d3fend_id,
        cri_statement_ids=list(rec.cri_statement_ids),
        guidance=rec.guidance,
        referenced_entity_ids=list(rec.referenced_entity_ids),
        effort=rec.effort,
    )


async def _build_mitigation_plan(
    project_id: str,
    project: Project,
    model: SystemModel,
    cri_service: ProjectCRIService,
    gateway: LLMGateway,
) -> MitigationPlanOut:
    ctx = await _gather_gap_context(project_id, model, project.atlas_enabled, cri_service)

    empty_residual = ResidualRiskOut(baseline_total_score=0.0, residual_total_score=0.0, risk_reduction=0.0)
    if not ctx.gaps:
        return MitigationPlanOut(
            tier=ctx.tier, recommendations=[], rejection_log=[], residual_risk=empty_residual, roadmap=[]
        )

    entity_names_by_id = {c.id: c.name for c in model.components}
    statement_texts = {s.profile_id: s.text for s in ctx.cri_statements}

    registry = AgentRegistry()
    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)
    registry.register(build_mitigation_agent(gateway, params))
    orchestrator = Orchestrator(registry, validate=validate_mitigation_grounding)

    result = orchestrator.invoke(
        MITIGATION_AGENT_NAME,
        {
            "gaps": ctx.gaps,
            "techniques_by_id": ctx.techniques_by_id,
            "d3fend_by_id": ctx.d3fend_by_id,
            "cri_statement_texts": statement_texts,
            "entity_names_by_id": entity_names_by_id,
            "entities_by_technique": entities_by_technique(ctx.path_result),
        },
    )
    recommendations: list[MitigationRecommendation] = result.output_artifacts["recommendations"]
    rejection_log = result.output_artifacts["rejection_log"]

    comparison = compute_residual_risk(
        ctx.path_result,
        ctx.gaps,
        recommendations,
        project.business_criticality,
        ctx.tier,
        ctx.cri_statements,
        ctx.regulatory_documents,
    )
    roadmap = build_roadmap(
        ctx.path_result,
        ctx.gaps,
        recommendations,
        project.business_criticality,
        ctx.tier,
        ctx.cri_statements,
        ctx.regulatory_documents,
    )

    return MitigationPlanOut(
        tier=ctx.tier,
        recommendations=[_recommendation_out(r) for r in recommendations],
        rejection_log=[
            RecommendationRejectionOut(
                recommendation_id=r.recommendation_id,
                technique_id=r.technique_id,
                reason_code=r.reason_code,
                detail=r.detail,
            )
            for r in rejection_log
        ],
        residual_risk=ResidualRiskOut(
            baseline_total_score=comparison.baseline_total_score,
            residual_total_score=comparison.residual_total_score,
            risk_reduction=comparison.risk_reduction,
        ),
        roadmap=[
            RoadmapPhaseOut(
                phase_number=phase.phase_number,
                recommendation_ids=[r.id for r in phase.recommendations],
                cumulative_risk_reduction=phase.cumulative_risk_reduction,
                phase_risk_reduction=phase.phase_risk_reduction,
                diagnostic_statements_closed=list(phase.diagnostic_statements_closed),
                attack_paths_closed=list(phase.attack_paths_closed),
            )
            for phase in roadmap
        ],
    )


@router.get("/{project_id}/system-model/mitigation-plan", response_model=MitigationPlanOut)
async def get_latest_mitigation_plan(
    project_id: str,
    _rate_limit: None = Depends(enforce_rate_limit),
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> MitigationPlanOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return await _build_mitigation_plan(project_id, project, model, cri_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central fact-provenance gate rejected agent output: {exc}"
        ) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/mitigation-plan", response_model=MitigationPlanOut
)
async def get_mitigation_plan_for_version(
    project_id: str,
    version: int,
    _rate_limit: None = Depends(enforce_rate_limit),
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> MitigationPlanOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return await _build_mitigation_plan(project_id, project, model, cri_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central fact-provenance gate rejected agent output: {exc}"
        ) from exc
