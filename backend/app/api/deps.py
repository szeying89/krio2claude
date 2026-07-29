from collections.abc import AsyncIterator, Callable

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.base import get_database
from app.orchestrator.events import EventBus, get_event_bus
from app.orchestrator.run_service import RunService
from app.services.cri.db_service import ProjectCRIService
from app.services.kb.refresh_service import KBRefreshService
from app.services.llm.gateway import LLMGateway
from app.services.llm.keys import MissingAPIKeyError, get_api_key
from app.services.llm.provider import AnthropicProvider, LLMProvider, OpenAIProvider
from app.services.project_service import ProjectService
from app.services.systemmodel.db_service import ProjectSystemModelService

_PROVIDER_BUILDERS: dict[str, Callable[..., LLMProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
}


async def get_session() -> AsyncIterator[AsyncSession]:
    db = get_database()
    async with db.session_factory() as session:
        yield session


def get_bus() -> EventBus:
    return get_event_bus()


async def get_run_service() -> AsyncIterator[RunService]:
    db = get_database()
    async with db.session_factory() as session:
        yield RunService(session, get_event_bus(), get_settings())


async def get_project_service() -> AsyncIterator[ProjectService]:
    db = get_database()
    async with db.session_factory() as session:
        yield ProjectService(session, get_settings())


def get_kb_refresh_service() -> KBRefreshService:
    return KBRefreshService(get_settings().kb_dir)


async def get_project_cri_service() -> AsyncIterator[ProjectCRIService]:
    db = get_database()
    async with db.session_factory() as session:
        yield ProjectCRIService(session, get_settings())


async def get_system_model_service() -> AsyncIterator[ProjectSystemModelService]:
    db = get_database()
    async with db.session_factory() as session:
        yield ProjectSystemModelService(session, get_settings())


def build_llm_provider(provider_name: str) -> LLMProvider:
    """Builds the real, network-calling provider for `provider_name` — raises
    `MissingAPIKeyError` (via `get_api_key`) if no credential is configured,
    which callers should turn into a clear "not configured" API response
    rather than a stack trace."""
    try:
        builder = _PROVIDER_BUILDERS[provider_name]
    except KeyError as exc:
        raise ValueError(f"unknown LLM provider {provider_name!r}") from exc
    api_key = get_api_key(provider_name)
    provider: LLMProvider = builder(api_key=api_key)
    return provider


def get_llm_gateway() -> LLMGateway:
    """FastAPI dependency: builds the configured provider from env/keyring
    credentials, turning a missing key into a 503 (a real, documented
    environment gap — see keys.py) rather than a 500 stack trace. Tests
    override this dependency with a FakeProvider-backed gateway rather than
    requiring real credentials."""
    settings = get_settings()
    try:
        provider = build_llm_provider(settings.llm_provider)
    except MissingAPIKeyError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"no LLM provider configured for model-building extraction: {exc}",
        ) from exc
    return LLMGateway(provider, cache_dir=settings.llm_cache_dir)
