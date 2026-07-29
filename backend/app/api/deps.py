from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.base import get_database
from app.orchestrator.events import EventBus, get_event_bus
from app.orchestrator.run_service import RunService
from app.services.kb.refresh_service import KBRefreshService
from app.services.project_service import ProjectService


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
