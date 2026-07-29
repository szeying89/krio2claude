from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import (
    get_project_cri_service,
    get_project_revision_service,
    get_project_service,
    get_system_model_service,
)
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.core.config import get_settings
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError
from app.services.enumeration.path_enumeration import PathEnumerationBudgetExceededError
from app.services.enumeration.ruleset import load_ruleset
from app.services.intel.models import ExtractedIntel
from app.services.intel.relevance import compute_relevance
from app.services.intel.storage import article_exists, read_article, read_extraction
from app.services.kb.snapshot import latest_snapshot_dir
from app.services.kb.snapshot import read_manifest as read_kb_manifest
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.revision.db_service import (
    ProjectNotFoundError as RevisionProjectNotFoundError,
)
from app.services.revision.db_service import ProjectRevisionService, RevisionNotFoundError
from app.services.revision.diff import compute_diff
from app.services.revision.intel_integration import IntelInput
from app.services.revision.models import RevisionSnapshot
from app.services.revision.snapshot import compute_snapshot
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)

router = APIRouter(prefix="/projects", tags=["revisions"])

_RULESET = load_ruleset()


class RevisionCreateIn(BaseModel):
    intel_article_content_hashes: list[str] = []


class RevisionOut(BaseModel):
    id: str
    parent_revision_id: str | None
    system_model_version: int
    kb_snapshot_hash: str | None
    cri_snapshot_hash: str | None
    intel_article_hashes: list[str]
    created_at: str
    paths: list[dict]
    adjudications: list[dict]
    rejection_count: int
    risk_total_score: float
    csf_rollup: list[dict]
    confidence: float
    currency: dict


class RevisionSummaryOut(BaseModel):
    id: str
    parent_revision_id: str | None
    created_at: str


class RevisionDiffOut(BaseModel):
    new_path_ids: list[str]
    removed_path_ids: list[str]
    changed_paths: list[dict]
    reopened_adjudication_ids: list[str]
    risk_score_delta: float
    csf_rollup_movement: list[dict]
    confidence_delta: float


def _revision_out(record) -> RevisionOut:
    snapshot = RevisionSnapshot.from_dict(record.snapshot)
    data = snapshot.to_dict()
    return RevisionOut(
        id=record.id,
        parent_revision_id=record.parent_revision_id,
        system_model_version=record.system_model_version,
        kb_snapshot_hash=record.kb_snapshot_hash,
        cri_snapshot_hash=record.cri_snapshot_hash,
        intel_article_hashes=list(record.intel_article_hashes),
        created_at=record.created_at.isoformat(),
        paths=data["paths"],
        adjudications=data["adjudications"],
        rejection_count=data["rejection_count"],
        risk_total_score=data["risk_total_score"],
        csf_rollup=data["csf_rollup"],
        confidence=data["confidence"],
        currency=data["currency"],
    )


async def _load_intel_inputs(content_hashes: list[str], model, settings) -> list[IntelInput]:
    inputs = []
    for content_hash in content_hashes:
        if not article_exists(settings.intel_dir, content_hash):
            raise HTTPException(status_code=404, detail=f"intel article {content_hash!r} not found")
        article_dir = settings.intel_dir / content_hash
        cached = read_extraction(article_dir)
        if cached is None:
            raise HTTPException(
                status_code=404, detail=f"intel article {content_hash!r} has no stored extraction"
            )
        extracted = ExtractedIntel.from_dict(cached["extracted_intel"])
        relevance = compute_relevance(extracted, model)
        record = read_article(article_dir)
        inputs.append(
            IntelInput(
                content_hash=content_hash, fetched_at=record.fetched_at, extracted=extracted, relevance=relevance
            )
        )
    return inputs


async def create_revision_for_project(
    project_id: str,
    body: RevisionCreateIn,
    project_service: ProjectService,
    model_service: ProjectSystemModelService,
    cri_service: ProjectCRIService,
    revision_service: ProjectRevisionService,
) -> RevisionOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc

    settings = get_settings()
    articles = await _load_intel_inputs(body.intel_article_content_hashes, model, settings)

    cri_statements = await cri_statements_with_bridge(cri_service, project_id)
    tiering = await cri_service.get_tiering(project_id)
    tier = tiering.tier if tiering is not None else None
    try:
        regulatory_documents = await cri_service.get_regulatory_documents(project_id)
    except CRIProfileNotUploadedError:
        regulatory_documents = {}
    try:
        cri_manifest = await cri_service.get_manifest(project_id)
        cri_snapshot_hash = cri_manifest.get("content_hash")
        cri_fetched_at = cri_manifest.get("fetched_at")
    except CRIProfileNotUploadedError:
        cri_snapshot_hash = None
        cri_fetched_at = None

    snapshot_kb = get_kb_snapshot()
    kb_dir = settings.kb_dir
    kb_snapshot_dir = latest_snapshot_dir(kb_dir)
    kb_snapshot_hash = kb_snapshot_dir.name if kb_snapshot_dir is not None else None
    kb_fetched_at = read_kb_manifest(kb_snapshot_dir)["fetched_at"] if kb_snapshot_dir is not None else None

    try:
        computed = compute_snapshot(
            model=model,
            ruleset=_RULESET,
            index=snapshot_kb.index if snapshot_kb is not None else None,
            techniques_by_id=snapshot_kb.techniques_by_id if snapshot_kb is not None else {},
            d3fend_catalog=snapshot_kb.d3fend_catalog if snapshot_kb is not None else [],
            cri_statements=cri_statements,
            regulatory_documents=regulatory_documents,
            tier=tier,
            business_criticality=project.business_criticality,
            atlas_enabled=project.atlas_enabled,
            articles=articles,
            kb_fetched_at=kb_fetched_at,
            cri_fetched_at=cri_fetched_at,
        )
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    parent = await revision_service.get_latest_revision(project_id)
    record = await revision_service.create_revision(
        project_id=project_id,
        parent_revision_id=parent.id if parent is not None else None,
        system_model_version=model.version,
        kb_snapshot_hash=kb_snapshot_hash,
        cri_snapshot_hash=cri_snapshot_hash,
        intel_article_hashes=body.intel_article_content_hashes,
        snapshot=computed,
    )
    return _revision_out(record)


@router.post("/{project_id}/revisions", response_model=RevisionOut)
async def create_revision(
    project_id: str,
    body: RevisionCreateIn,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
) -> RevisionOut:
    return await create_revision_for_project(
        project_id, body, project_service, model_service, cri_service, revision_service
    )


@router.get("/{project_id}/revisions", response_model=list[RevisionSummaryOut])
async def list_revisions(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
) -> list[RevisionSummaryOut]:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        revisions = await revision_service.list_revisions(project_id)
    except RevisionProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return [
        RevisionSummaryOut(id=r.id, parent_revision_id=r.parent_revision_id, created_at=r.created_at.isoformat())
        for r in revisions
    ]


@router.get("/{project_id}/revisions/{revision_id}", response_model=RevisionOut)
async def get_revision(
    project_id: str,
    revision_id: str,
    project_service: ProjectService = Depends(get_project_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
) -> RevisionOut:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        record = await revision_service.get_revision(project_id, revision_id)
    except RevisionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="revision not found") from exc
    return _revision_out(record)


@router.get("/{project_id}/revisions/{revision_id}/diff", response_model=RevisionDiffOut)
async def get_revision_diff(
    project_id: str,
    revision_id: str,
    project_service: ProjectService = Depends(get_project_service),
    revision_service: ProjectRevisionService = Depends(get_project_revision_service),
) -> RevisionDiffOut:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        record = await revision_service.get_revision(project_id, revision_id)
    except RevisionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="revision not found") from exc
    if record.parent_revision_id is None:
        raise HTTPException(status_code=409, detail="this is the initial revision; it has no parent to diff against")
    parent_record = await revision_service.get_revision(project_id, record.parent_revision_id)

    diff = compute_diff(
        RevisionSnapshot.from_dict(parent_record.snapshot), RevisionSnapshot.from_dict(record.snapshot)
    )
    return RevisionDiffOut(
        new_path_ids=list(diff.new_path_ids),
        removed_path_ids=list(diff.removed_path_ids),
        changed_paths=[
            {"path_id": c.path_id, "previous_likelihood": c.previous_likelihood, "new_likelihood": c.new_likelihood, "delta": c.delta}
            for c in diff.changed_paths
        ],
        reopened_adjudication_ids=list(diff.reopened_adjudication_ids),
        risk_score_delta=diff.risk_score_delta,
        csf_rollup_movement=[
            {"function": m.function, "previous_density": m.previous_density, "new_density": m.new_density, "delta": m.delta}
            for m in diff.csf_rollup_movement
        ],
        confidence_delta=diff.confidence_delta,
    )
