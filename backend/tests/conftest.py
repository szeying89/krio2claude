from collections.abc import AsyncIterator

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.db.base import get_database, reset_database
from app.orchestrator.events import reset_event_bus


@pytest_asyncio.fixture
async def app_env(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("TM_DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("TM_DATA_DIR", str(tmp_path / "data"))
    reset_database()
    reset_event_bus()

    db = get_database()
    await db.create_all()
    yield
    await db.dispose()
    reset_database()
    reset_event_bus()


@pytest_asyncio.fixture
async def client(app_env) -> AsyncIterator[AsyncClient]:
    # Import after app_env resets the settings-dependent singletons so the
    # app's dependencies pick up the temp test database.
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
