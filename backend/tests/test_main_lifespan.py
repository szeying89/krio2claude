"""Security-review fix: app.main's lifespan hardens permissions on every
top-level data directory it creates, and on the SQLite database file
once it exists, rather than leaving them at the default (typically
world-readable) process umask.

The `client`/`app_env` fixtures used by the rest of this suite create
the database directly (via `get_database().create_all()`) without
running the real ASGI lifespan, so this test drives `lifespan()` itself
as an async context manager to actually exercise it.
"""

import stat

import pytest

from app.core.config import get_settings
from app.db.base import reset_database
from app.main import lifespan
from app.services.sqlite_path import sqlite_db_path


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.asyncio
async def test_lifespan_creates_owner_only_data_directories(tmp_path, monkeypatch):
    monkeypatch.setenv("TM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TM_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    reset_database()
    try:
        settings = get_settings()
        async with lifespan(app=None):  # the app object itself is unused by this lifespan
            for directory in (
                settings.data_dir, settings.runs_dir, settings.projects_dir,
                settings.kb_dir, settings.cri_dir, settings.intel_dir, settings.cache_dir,
            ):
                assert directory.is_dir()
                assert _mode(directory) == 0o700

            db_path = sqlite_db_path(settings.database_url)
            assert db_path is not None
            assert db_path.exists()
            assert _mode(db_path) == 0o600
    finally:
        reset_database()


@pytest.mark.asyncio
async def test_lifespan_hardens_permissions_even_under_a_permissive_umask(tmp_path, monkeypatch):
    import os

    monkeypatch.setenv("TM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("TM_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'app.db'}")
    reset_database()
    old_umask = os.umask(0o000)
    try:
        settings = get_settings()
        async with lifespan(app=None):
            assert _mode(settings.data_dir) == 0o700
            db_path = sqlite_db_path(settings.database_url)
            assert db_path is not None
            assert _mode(db_path) == 0o600
    finally:
        os.umask(old_umask)
        reset_database()
