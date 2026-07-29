from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import (
    get_llm_gateway,
    get_project_cri_service,
    get_project_review_service,
    get_project_revision_service,
    get_project_service,
    get_system_model_service,
)
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.api.revisions import RevisionCreateIn, RevisionOut, create_revision_for_project
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.critique_agent import (
    AGENT_NAME as CRITIQUE_AGENT_NAME,
)
from app.services.assurance.critique_agent import build_critique_agent, validate_critique_grounding
from app.services.assurance.review_db_service import (
    ProjectNotFoundError as ReviewProjectNotFoundError,
)
from app.services.assurance.review_db_service import (
    ProjectReviewService,
    ReviewItemAlreadyDecidedError,
    ReviewItemNotFoundError,
)
from app.services.cri.db_service import ProjectCRIService
from app.services.enumeration.agent import (
    AGENT_NAME as ENUMERATION_AGENT_NAME,
)
from app.services.enumeration.agent import build_enumeration_agent, validate_enumeration_grounding
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.gap_analysis import (
    compute_technique_gaps,
    entities_by_technique,
    techniques_in_paths,
)
from app.services.mitigation.inventory import build_control_inventory
from app.services.modelbuilding.agent import documents_input_for_project, run_model_building
from app.services.project_service import Project, ProjectNotFoundError, ProjectService
from app.services.revision.db_service import ProjectRevisionService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["review"])

_RULESET = load_ruleset()


class ReviewItemOut(BaseModel):
    id: str
    category: str
    severity: str
    rationale: str
    cited_element_ids: list[str]
    cited_statement_ids: list[str]
    status: str
    decision_reason: str | None
    created_at: str
    decided_at: str | None


def _item_out(record) -> ReviewItemOut:
    return ReviewItemOut(
        id=record.id,
        category=record.category,
        severity=record.severity,
        rationale=record.rationale,
        cited_element_ids=list(record.cited_element_ids),
        cited_statement_ids=list(record.cited_statement_ids),
        status=record.status,
        decision_reason=record.decision_reason,
        created_at=record.created_at.isoformat(),
        decided_at=record.decided_at.isoformat() if record.decided_at is not None else None,
    )


async def _gather_critique_inputs(
    project: Project, model: SystemModel, cri_service: ProjectCRIService
) -> dict:
    cri_statements = await cri_statements_with_bridge(cri_service, project.id)
    tiering = await cri_service.get_tiering(project.id)
    tier = tiering.tier if tiering is not None else None

    gaps: list = []
    entities_map: dict = {}
    snapshot = get_kb_snapshot()
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
        entities_map = entities_by_technique(path_result)
        inventory = build_control_inventory(model.declared_controls, snapshot.d3fend_catalog, cri_statements)
        gaps = compute_technique_gaps(
            technique_ids, snapshot.techniques_by_id, inventory, cri_statements, tier
        )

    return {
        "cri_statements": cri_statements,
        "tier": tier,
        "gaps": gaps,
        "entities_by_technique": entities_map,
    }


@router.post("/{project_id}/review-items/generate", response_model=list[ReviewItemOut])
async def generate_review_items(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    review_service: ProjectReviewService = Depends(get_project_review_service),
    gateway: LLMGateway = Depends(get_llm_gateway),
) -> list[ReviewItemOut]:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc

    try:
        critique_inputs = await _gather_critique_inputs(project, model, cri_service)

        snapshot = get_kb_snapshot()
        adjudicated_threats = []
        if snapshot is not None:
            enum_registry = AgentRegistry()
            enum_registry.register(build_enumeration_agent(_RULESET, snapshot.index))
            enum_orchestrator = Orchestrator(enum_registry, validate=validate_enumeration_grounding)
            enum_result = enum_orchestrator.invoke(
                ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": project.atlas_enabled}
            )
            adjudicated_threats = enum_result.output_artifacts["adjudicated_threats"]

        settings = get_settings()
        params = CompletionParams(model=settings.llm_model)
        documents = documents_input_for_project(project)
        draft = run_model_building(gateway, params, documents)

        registry = AgentRegistry()
        registry.register(build_critique_agent(gateway, params))
        orchestrator = Orchestrator(registry, validate=validate_critique_grounding)
        result = orchestrator.invoke(
            CRITIQUE_AGENT_NAME,
            {
                "model": model,
                "adjudicated_threats": adjudicated_threats,
                "gaps": critique_inputs["gaps"],
                "entities_by_technique": critique_inputs["entities_by_technique"],
                "assumptions": draft.assumptions,
                "tier": critique_inputs["tier"],
                "cri_statements": critique_inputs["cri_statements"],
            },
        )
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central critique grounding gate rejected agent output: {exc}"
        ) from exc

    latest_revision = await revision_service.get_latest_revision(project_id)
    records = await review_service.create_review_items(
        project_id,
        latest_revision.id if latest_revision is not None else None,
        result.output_artifacts["review_items"],
    )
    return [_item_out(r) for r in records]


@router.get("/{project_id}/review-items", response_model=list[ReviewItemOut])
async def list_review_items(
    project_id: str,
    status: str | None = None,
    project_service: ProjectService = Depends(get_project_service),
    review_service: ProjectReviewService = Depends(get_project_review_service),
) -> list[ReviewItemOut]:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        records = await review_service.list_items(project_id, status)
    except ReviewProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return [_item_out(r) for r in records]


@router.get("/{project_id}/review-items/{item_id}", response_model=ReviewItemOut)
async def get_review_item(
    project_id: str,
    item_id: str,
    project_service: ProjectService = Depends(get_project_service),
    review_service: ProjectReviewService = Depends(get_project_review_service),
) -> ReviewItemOut:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        record = await review_service.get_item(project_id, item_id)
    except ReviewItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="review item not found") from exc
    return _item_out(record)


class ReviewAuditEntryOut(BaseModel):
    action: str
    reason: str | None
    created_at: str


@router.get("/{project_id}/review-items/{item_id}/audit", response_model=list[ReviewAuditEntryOut])
async def get_review_item_audit(
    project_id: str,
    item_id: str,
    project_service: ProjectService = Depends(get_project_service),
    review_service: ProjectReviewService = Depends(get_project_review_service),
) -> list[ReviewAuditEntryOut]:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        await review_service.get_item(project_id, item_id)
    except ReviewItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="review item not found") from exc

    entries = await review_service.list_audit_entries(item_id)
    return [
        ReviewAuditEntryOut(action=e.action, reason=e.reason, created_at=e.created_at.isoformat())
        for e in entries
    ]


class ReviewDecisionIn(BaseModel):
    decision: str  # "accept" | "reject"
    reason: str | None = None


class ReviewDecisionOut(BaseModel):
    item: ReviewItemOut
    new_revision: RevisionOut | None = None


@router.post("/{project_id}/review-items/{item_id}/decide", response_model=ReviewDecisionOut)
async def decide_review_item(
    project_id: str,
    item_id: str,
    body: ReviewDecisionIn,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
    review_service: ProjectReviewService = Depends(get_project_review_service),
) -> ReviewDecisionOut:
    if body.decision not in ("accept", "reject"):
        raise HTTPException(status_code=422, detail="decision must be 'accept' or 'reject'")

    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        await review_service.get_item(project_id, item_id)
    except ReviewItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="review item not found") from exc

    try:
        record = await review_service.decide_item(project_id, item_id, body.decision, body.reason)
    except ReviewItemAlreadyDecidedError as exc:
        raise HTTPException(status_code=409, detail="this review item has already been decided") from exc

    new_revision_out = None
    if body.decision == "accept":
        # Accepting re-runs exactly the same downstream re-computation a
        # revision already performs — the invalidation graph's own
        # minimal-re-run machinery, not a bespoke path. Any error here
        # (e.g. no system model at all) is a real error and propagates
        # exactly as it would from POST .../revisions directly.
        new_revision_out = await create_revision_for_project(
            project_id,
            RevisionCreateIn(intel_article_content_hashes=[]),
            project_service,
            model_service,
            cri_service,
            revision_service,
        )

    return ReviewDecisionOut(item=_item_out(record), new_revision=new_revision_out)
