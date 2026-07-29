from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel

from app.api.deps import (
    get_llm_gateway,
    get_project_cri_service,
    get_project_revision_service,
    get_project_service,
    get_system_model_service,
)
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.rubric import compute_coverage_report
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
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
from app.services.mitigation.agent import AGENT_NAME as MITIGATION_AGENT_NAME
from app.services.mitigation.agent import build_mitigation_agent
from app.services.mitigation.gap_analysis import (
    compute_technique_gaps,
    entities_by_technique,
    techniques_in_paths,
)
from app.services.mitigation.inventory import build_control_inventory
from app.services.mitigation.residual_risk import compute_residual_risk
from app.services.mitigation.roadmap import build_roadmap
from app.services.modelbuilding.agent import documents_input_for_project, run_model_building
from app.services.project_service import Project, ProjectNotFoundError, ProjectService
from app.services.reporting.agent import (
    AGENT_NAME as REPORTING_AGENT_NAME,
)
from app.services.reporting.agent import build_reporting_agent, validate_reporting_fact_provenance
from app.services.reporting.assemble import assemble_report_data
from app.services.reporting.export_csv import export_csv
from app.services.reporting.export_json import export_json
from app.services.reporting.export_otm import export_otm
from app.services.reporting.export_pdf import markdown_to_pdf_bytes
from app.services.reporting.models import ReportData
from app.services.reporting.render import RENDERERS
from app.services.revision.db_service import ProjectRevisionService
from app.services.revision.models import ThreatLandscapeCurrency
from app.services.risk.register import build_risk_register
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["reports"])

_RULESET = load_ruleset()
_AUDIENCES = ("executive", "ciso", "technical")


async def _gather_report_data(
    project: Project,
    model: SystemModel,
    cri_service: ProjectCRIService,
    revision_service: ProjectRevisionService,
    gateway: LLMGateway,
) -> ReportData:
    cri_statements = await cri_statements_with_bridge(cri_service, project.id)
    tiering = await cri_service.get_tiering(project.id)
    tier = tiering.tier if tiering is not None else None
    try:
        regulatory_documents = await cri_service.get_regulatory_documents(project.id)
    except CRIProfileNotUploadedError:
        regulatory_documents = {}

    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)

    snapshot = get_kb_snapshot()
    gaps: list = []
    adjudicated_threats: list = []
    rejection_log: list = []
    candidate_count = 0
    risk_findings: list = []
    csf_rollup: list = []
    residual_risk = None
    roadmap: list = []
    recommendations: list = []

    if snapshot is not None:
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

        risk_register = build_risk_register(
            path_result, gaps, project.business_criticality, tier, cri_statements, regulatory_documents
        )
        risk_findings = list(risk_register.findings)
        csf_rollup = list(risk_register.csf_rollup)

        enum_registry = AgentRegistry()
        enum_registry.register(build_enumeration_agent(_RULESET, snapshot.index))
        enum_orchestrator = Orchestrator(enum_registry, validate=validate_enumeration_grounding)
        enum_result = enum_orchestrator.invoke(
            ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": project.atlas_enabled}
        )
        adjudicated_threats = enum_result.output_artifacts["adjudicated_threats"]
        rejection_log = enum_result.output_artifacts["rejection_log"]
        candidate_count = enum_result.output_artifacts["candidate_count"]

        mitigation_registry = AgentRegistry()
        mitigation_registry.register(build_mitigation_agent(gateway, params))
        mitigation_orchestrator = Orchestrator(mitigation_registry)
        mitigation_result = mitigation_orchestrator.invoke(
            MITIGATION_AGENT_NAME,
            {
                "gaps": gaps,
                "techniques_by_id": snapshot.techniques_by_id,
                "d3fend_by_id": {d.id: d for d in snapshot.d3fend_catalog},
                "cri_statement_texts": {s.profile_id: s.text for s in cri_statements},
                "entity_names_by_id": {c.id: c.name for c in model.components},
                "entities_by_technique": entities_by_technique(path_result),
            },
        )
        recommendations = mitigation_result.output_artifacts["recommendations"]
        if recommendations:
            comparison = compute_residual_risk(
                path_result, gaps, recommendations, project.business_criticality, tier,
                cri_statements, regulatory_documents,
            )
            residual_risk = comparison
            roadmap = list(
                build_roadmap(
                    path_result, gaps, recommendations, project.business_criticality, tier,
                    cri_statements, regulatory_documents,
                )
            )

    enumeration_result = build_enumeration_result(model, _RULESET)
    documents = documents_input_for_project(project)
    draft = run_model_building(gateway, params, documents)
    confidence = compute_coverage_report(
        model=model,
        enumeration_result=enumeration_result,
        candidate_count=candidate_count,
        adjudicated_threats=adjudicated_threats,
        rejection_log=rejection_log,
        gaps=gaps,
        assumptions=draft.assumptions,
    )

    latest_revision = await revision_service.get_latest_revision(project.id)
    currency = None
    if latest_revision is not None:
        snapshot_dict = latest_revision.snapshot
        currency_dict = snapshot_dict.get("currency", {})
        currency = ThreatLandscapeCurrency(
            kb_fetched_at=currency_dict.get("kb_fetched_at"),
            cri_fetched_at=currency_dict.get("cri_fetched_at"),
            intel_article_count=currency_dict.get("intel_article_count", 0),
            latest_intel_fetched_at=currency_dict.get("latest_intel_fetched_at"),
        )

    return assemble_report_data(
        project_name=project.name,
        business_criticality=project.business_criticality.value
        if hasattr(project.business_criticality, "value")
        else str(project.business_criticality),
        model=model,
        confidence=confidence,
        risk_findings=risk_findings,
        csf_rollup=csf_rollup,
        tiering=tiering,
        gaps=gaps,
        residual_risk=residual_risk,
        roadmap=roadmap,
        recommendations=recommendations,
        adjudicated_threats=adjudicated_threats,
        rejection_log=rejection_log,
        assumptions=draft.assumptions,
        currency=currency,
        has_cri=bool(cri_statements),
    )


async def _get_project_and_model(
    project_id: str, project_service: ProjectService, model_service: ProjectSystemModelService
) -> tuple[Project, SystemModel]:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return project, model


async def _build_narratives(data: ReportData, gateway: LLMGateway) -> dict[str, str]:
    settings = get_settings()
    params = CompletionParams(model=settings.llm_model)
    registry = AgentRegistry()
    registry.register(build_reporting_agent(gateway, params))
    orchestrator = Orchestrator(registry, validate=validate_reporting_fact_provenance)
    result = orchestrator.invoke(REPORTING_AGENT_NAME, {"report_data": data})
    return dict(result.output_artifacts["narratives"])


class ReportOut(BaseModel):
    audience: str
    markdown: str


@router.get("/{project_id}/reports/{audience}", response_model=ReportOut)
async def get_report(
    project_id: str,
    audience: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> ReportOut:
    if audience not in _AUDIENCES:
        raise HTTPException(status_code=404, detail=f"unknown audience {audience!r}")
    project, model = await _get_project_and_model(project_id, project_service, model_service)

    try:
        data = await _gather_report_data(project, model, cri_service, revision_service, gateway)
        narratives = await _build_narratives(data, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central fact-provenance gate rejected agent output: {exc}"
        ) from exc

    narrative = narratives.get(audience, "")
    markdown = RENDERERS[audience](data, narrative)
    return ReportOut(audience=audience, markdown=markdown)


@router.get("/{project_id}/reports/{audience}/pdf")
async def get_report_pdf(
    project_id: str,
    audience: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> Response:
    if audience not in _AUDIENCES:
        raise HTTPException(status_code=404, detail=f"unknown audience {audience!r}")
    project, model = await _get_project_and_model(project_id, project_service, model_service)

    try:
        data = await _gather_report_data(project, model, cri_service, revision_service, gateway)
        narratives = await _build_narratives(data, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central fact-provenance gate rejected agent output: {exc}"
        ) from exc

    narrative = narratives.get(audience, "")
    markdown = RENDERERS[audience](data, narrative)
    pdf_bytes = markdown_to_pdf_bytes(f"{project.name} — {audience.title()} Report", markdown)
    return Response(content=pdf_bytes, media_type="application/pdf")


@router.get("/{project_id}/exports/otm")
async def get_otm_export(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> dict:
    _, model = await _get_project_and_model(project_id, project_service, model_service)
    return export_otm(model)


@router.get("/{project_id}/exports/csv")
async def get_csv_export(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> Response:
    project, model = await _get_project_and_model(project_id, project_service, model_service)
    try:
        data = await _gather_report_data(project, model, cri_service, revision_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(content=export_csv(data), media_type="text/csv")


@router.get("/{project_id}/exports/json")
async def get_json_export(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> Response:
    project, model = await _get_project_and_model(project_id, project_service, model_service)
    try:
        data = await _gather_report_data(project, model, cri_service, revision_service, gateway)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(content=export_json(data), media_type="application/json")
