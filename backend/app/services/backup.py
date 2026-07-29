"""Task 24: backup/restore for `./data`, plus the SQLite database file
(runs, revisions, review items, audit log, and every other piece of
persisted state this app has all live there) -- restoring only `data_dir`
without the database would not reproduce prior runs, revisions, or
scores, so the archive covers both.

Invoked as `python -m app.services.backup create <archive.tar.gz>` or
`python -m app.services.backup restore <archive.tar.gz>` (see the
top-level docs for the full operability runbook). This is a local,
single-tenant v1 app (Requirement 1): there is no live-replication or
point-in-time story here, just "stop the server, snapshot everything,
restore it later" -- consistent with the rest of this build's scope.
"""

from __future__ import annotations

import argparse
import tarfile
from pathlib import Path

from app.core.config import Settings, get_settings

_SQLITE_PREFIX = "sqlite+aiosqlite:///"
_DATA_ARCNAME = "data"
_DB_ARCNAME = "db.sqlite3"


class BackupError(Exception):
    pass


def _sqlite_db_path(database_url: str) -> Path | None:
    if not database_url.startswith(_SQLITE_PREFIX):
        return None
    return Path(database_url[len(_SQLITE_PREFIX) :])


def create_backup(settings: Settings, dest: Path) -> Path:
    """Writes a single tar.gz archive containing `data_dir` (under
    `data/`) and the SQLite database file, if configured, (as
    `db.sqlite3`). Returns `dest`."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    db_path = _sqlite_db_path(settings.database_url)

    with tarfile.open(dest, "w:gz") as tar:
        if settings.data_dir.exists():
            tar.add(settings.data_dir, arcname=_DATA_ARCNAME)
        if db_path is not None and db_path.exists():
            tar.add(db_path, arcname=_DB_ARCNAME)
    return dest


def restore_backup(settings: Settings, archive: Path) -> None:
    """Extracts an archive written by `create_backup` back into
    `settings.data_dir` and the configured SQLite database file,
    overwriting whatever is currently there. Uses tarfile's `"data"`
    extraction filter (Python 3.12+) so no archive member can escape the
    intended destinations via a path-traversal name."""
    if not archive.exists():
        raise BackupError(f"backup archive not found: {archive}")

    db_path = _sqlite_db_path(settings.database_url)
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name == _DATA_ARCNAME or member.name.startswith(f"{_DATA_ARCNAME}/"):
                tar.extract(member, path=settings.data_dir.parent, filter="data")
            elif member.name == _DB_ARCNAME:
                if db_path is None:
                    raise BackupError(
                        "archive contains a database file but the current settings have no "
                        "SQLite database_url to restore it to"
                    )
                db_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise BackupError("archive's db.sqlite3 member is not a regular file")
                db_path.write_bytes(extracted.read())


def run() -> None:
    parser = argparse.ArgumentParser(description="Backup/restore ./data and the SQLite database.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create", help="write a new backup archive")
    create_parser.add_argument("archive", type=Path)

    restore_parser = subparsers.add_parser("restore", help="restore from a backup archive")
    restore_parser.add_argument("archive", type=Path)

    args = parser.parse_args()
    settings = get_settings()

    if args.command == "create":
        dest = create_backup(settings, args.archive)
        print(f"backup written to {dest}")
    elif args.command == "restore":
        restore_backup(settings, args.archive)
        print(f"restored from {args.archive}")


if __name__ == "__main__":
    run()
