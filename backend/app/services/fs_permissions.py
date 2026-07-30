"""Restrictive filesystem permissions for locally-stored, potentially
sensitive data (uploaded design documents, KB/CRI/intel snapshots, the
SQLite database).

Security-review finding, fixed here: every directory and file this
platform creates was made with default OS permissions (typically
`0755`/`0644` under a standard umask -- world-readable), so any other
local account on a shared host could read project data, licensed CRI
content, uploaded documents, and the audit log. This is explicitly a
local, single-tenant tool (Requirement 1) with no in-app multi-user
isolation, so filesystem permissions are the *only* boundary between
this data and another account on the same machine -- they need to
actually be restrictive, not left at the process umask's default.
"""

from __future__ import annotations

from pathlib import Path

DIR_MODE = 0o700
FILE_MODE = 0o600


def secure_mkdir(path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
    """Like `Path.mkdir`, but the resulting directory is owner-only
    regardless of the process umask (`mkdir(mode=...)` alone is masked
    by umask on POSIX, so the mode is re-applied explicitly afterward)."""
    path.mkdir(parents=parents, exist_ok=exist_ok, mode=DIR_MODE)
    path.chmod(DIR_MODE)


def secure_chmod_tree(path: Path) -> None:
    """Recursively locks down every directory and file under `path`
    (inclusive) to owner-only. Used right before an atomic
    temp-dir-then-rename publish (Task 3/18's snapshot-writing pattern),
    so everything written into the temp directory during construction
    ends up with the intended permissions in one place, regardless of
    how each individual write call created it."""
    for entry in path.rglob("*"):
        entry.chmod(FILE_MODE if entry.is_file() else DIR_MODE)
    path.chmod(DIR_MODE)
