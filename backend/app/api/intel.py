from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator

from app.api.deps import (
    get_audit_log_service,
    get_llm_gateway,
    get_project_service,
    get_system_model_service,
)
from app.api.rate_limit import enforce_rate_limit
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.audit.service import AuditLogService
from app.services.content_addressing import is_valid_content_hash
from app.services.intel.agent import AGENT_NAME, build_intel_agent, validate_intel_extraction
from app.services.intel.fetch import FetchError, fetch_article
from app.services.intel.models import ExtractedIntel
from app.services.intel.relevance import compute_relevance
from app.services.intel.ssrf_guard import SSRFBlockedError
from app.services.intel.storage import (
    article_exists,
    read_article,
    read_extraction,
    write_article,
    write_extraction,
)
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import ProjectSystemModelService, SystemModelNotFoundError

router = APIRouter(tags=["intel"])


class IntelIngestIn(BaseModel):
    url: str | None = None
    text: str | None = None

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "IntelIngestIn":
        if (self.url is None) == (self.text is None):
            raise ValueError("exactly one of url or text must be provided")
        return self


class ExtractedIntelOut(BaseModel):
    technique_ids: list[str]
    cves: list[str]
    affected_products: list[dict]
    actor: str | None
    targeted_sectors: list[str]
    campaign_start: str | None
    campaign_end: str | None
    ttp_summary: str
    source_credibility: str


class IntelArticleOut(BaseModel):
    content_hash: str
    source_url: str | None
    fetched_at: str
    extracted_intel: ExtractedIntelOut
    injection_indicators: list[str]


def _extracted_out(extracted: ExtractedIntel) -> ExtractedIntelOut:
    data = extracted.to_dict()
    return ExtractedIntelOut(**data)


@router.post("/intel/articles", response_model=IntelArticleOut)
async def ingest_article(
    body: IntelIngestIn,
    _rate_limit: None = Depends(enforce_rate_limit),
    gateway: LLMGateway = Depends(get_llm_gateway),
    audit: AuditLogService = Depends(get_audit_log_service),
) -> IntelArticleOut:
    settings = get_settings()

    if body.url is not None:
        try:
            raw_text, _final_url = fetch_article(body.url)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=400, detail=f"URL rejected: {exc}") from exc
        except FetchError as exc:
            raise HTTPException(status_code=502, detail=f"could not fetch article: {exc}") from exc
        source_url = body.url
    else:
        raw_text = body.text or ""
        source_url = None

    fetched_at = datetime.now(UTC).isoformat()
    article_dir = write_article(settings.intel_dir, raw_text, source_url, fetched_at)

    cached = read_extraction(article_dir)
    if cached is not None:
        extracted = ExtractedIntel.from_dict(cached["extracted_intel"])
        injection_indicators = tuple(cached["injection_indicators"])
    else:
        params = CompletionParams(model=settings.llm_model)
        registry = AgentRegistry()
        registry.register(build_intel_agent(gateway, params))
        orchestrator = Orchestrator(registry, validate=validate_intel_extraction)
        try:
            result = orchestrator.invoke(AGENT_NAME, {"article_text": raw_text})
        except ValidationError as exc:
            raise HTTPException(
                status_code=500, detail=f"central intel validation gate rejected agent output: {exc}"
            ) from exc
        extracted = result.output_artifacts["extracted_intel"]
        injection_indicators = result.output_artifacts["injection_indicators"]
        write_extraction(article_dir, extracted.to_dict(), injection_indicators)
        await audit.record(
            "agent.invoked",
            f"{AGENT_NAME} agent invoked ({len(result.trajectory.tool_calls)} tool calls)",
            detail={
                "agent_name": AGENT_NAME,
                "tool_call_count": len(result.trajectory.tool_calls),
                "cache_hit": result.cache_hit,
                "latency_ms": result.trajectory.latency_ms,
            },
        )

    record = read_article(article_dir)
    await audit.record(
        "intel.ingested",
        f"intel article {record.content_hash} ingested"
        + (f" from {source_url}" if source_url else " from pasted text"),
        detail={
            "content_hash": record.content_hash,
            "source_url": source_url,
            "technique_ids": list(extracted.technique_ids),
            "injection_indicator_count": len(injection_indicators),
        },
    )
    return IntelArticleOut(
        content_hash=record.content_hash,
        source_url=record.source_url,
        fetched_at=record.fetched_at,
        extracted_intel=_extracted_out(extracted),
        injection_indicators=list(injection_indicators),
    )


@router.get("/intel/articles/{content_hash}", response_model=IntelArticleOut)
async def get_article(content_hash: str) -> IntelArticleOut:
    if not is_valid_content_hash(content_hash):
        raise HTTPException(status_code=404, detail="article not found")
    settings = get_settings()
    if not article_exists(settings.intel_dir, content_hash):
        raise HTTPException(status_code=404, detail="article not found")

    article_dir = settings.intel_dir / content_hash
    record = read_article(article_dir)
    cached = read_extraction(article_dir)
    if cached is None:
        raise HTTPException(status_code=404, detail="article has no stored extraction")

    return IntelArticleOut(
        content_hash=record.content_hash,
        source_url=record.source_url,
        fetched_at=record.fetched_at,
        extracted_intel=_extracted_out(ExtractedIntel.from_dict(cached["extracted_intel"])),
        injection_indicators=list(cached["injection_indicators"]),
    )


class RelevanceOut(BaseModel):
    score: float
    reasons: list[str]
    matched_entity_ids: list[str]


@router.get(
    "/projects/{project_id}/intel/articles/{content_hash}/relevance", response_model=RelevanceOut
)
async def get_article_relevance(
    project_id: str,
    content_hash: str,
    declared_sector: str | None = None,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> RelevanceOut:
    try:
        await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc

    if not is_valid_content_hash(content_hash):
        raise HTTPException(status_code=404, detail="article not found")
    settings = get_settings()
    if not article_exists(settings.intel_dir, content_hash):
        raise HTTPException(status_code=404, detail="article not found")
    cached = read_extraction(settings.intel_dir / content_hash)
    if cached is None:
        raise HTTPException(status_code=404, detail="article has no stored extraction")

    extracted = ExtractedIntel.from_dict(cached["extracted_intel"])
    result = compute_relevance(extracted, model, declared_sector)
    return RelevanceOut(
        score=result.score, reasons=list(result.reasons), matched_entity_ids=list(result.matched_entity_ids)
    )
