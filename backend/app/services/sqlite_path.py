"""Resolves a `sqlite+aiosqlite:///` database URL to its underlying file
path. Shared by `app/services/backup.py` (backup/restore needs the raw
file) and `app/main.py` (permission-hardening the file on startup) --
promoted out of `backup.py`'s own private helper the moment a second
real consumer needed it.
"""

from __future__ import annotations

from pathlib import Path

_SQLITE_PREFIX = "sqlite+aiosqlite:///"


def sqlite_db_path(database_url: str) -> Path | None:
    if not database_url.startswith(_SQLITE_PREFIX):
        return None
    return Path(database_url[len(_SQLITE_PREFIX) :])
