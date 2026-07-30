from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import Settings, get_settings


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, settings: Settings) -> None:
        self.engine = create_async_engine(settings.database_url, echo=False)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def create_all(self) -> None:
        import app.models  # noqa: F401  (ensures all ORM classes are registered before DDL)

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session


_db: Database | None = None


def get_database() -> Database:
    global _db
    if _db is None:
        _db = Database(get_settings())
    return _db


def reset_database() -> None:
    """Test-only hook: drop the cached Database so the next get_database()
    picks up current settings (e.g. a fresh temp sqlite file per test)."""
    global _db
    _db = None
