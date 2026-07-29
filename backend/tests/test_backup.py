"""Task 24: backup/restore for `./data` and the SQLite database. Freezes
a real project through the live app, backs it up, simulates total data
loss (both `data_dir` and the database file deleted from disk), restores
from the archive, and verifies -- through a brand-new database
connection that never saw the "before" state, and a direct read of the
restored document file -- that the project, its uploaded document, and
its frozen system model all really came back, not just that no exception
was raised.
"""

import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.deps import get_llm_gateway
from app.core.config import get_settings
from app.services.backup import BackupError, create_backup, restore_backup
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
}

DESIGN_DOC = b"""\
# Payments Platform

The gateway forwards requests to the payment processor.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
```
"""

EXTRACTION = json.dumps(
    {"components": [], "actors": [], "flows": [], "assets": [], "trust_zones": [], "declared_controls": []}
)


def _db_path_from_url(database_url: str) -> Path:
    return Path(database_url.removeprefix("sqlite+aiosqlite:///"))


@pytest.mark.asyncio
async def test_backup_and_restore_reproduces_a_project_its_document_and_its_frozen_model(
    client, tmp_path
):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = lambda: LLMGateway(
        FakeProvider(respond=lambda _p: EXTRACTION), cache_dir=tmp_path / "llm-cache"
    )
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC, "text/markdown")},
        )
        freeze = await client.post(f"/projects/{project_id}/system-model")
        assert freeze.status_code == 200
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    settings = get_settings()
    db_path = _db_path_from_url(settings.database_url)
    assert db_path.exists()

    doc_dir = settings.projects_dir / project_id / "documents"
    original_doc_files = list(doc_dir.iterdir())
    assert len(original_doc_files) == 1
    original_doc_bytes = original_doc_files[0].read_bytes()

    archive = tmp_path / "backup.tar.gz"
    create_backup(settings, archive)
    assert archive.exists()

    # Simulate total data loss -- this test never issues another request
    # through `client` after this point, so there is no stale live
    # connection to the deleted file to worry about.
    shutil.rmtree(settings.data_dir)
    db_path.unlink()
    assert not settings.data_dir.exists()
    assert not db_path.exists()

    restore_backup(settings, archive)

    assert settings.data_dir.exists()
    assert db_path.exists()

    restored_doc_files = list((settings.projects_dir / project_id / "documents").iterdir())
    assert len(restored_doc_files) == 1
    assert restored_doc_files[0].read_bytes() == original_doc_bytes

    fresh_engine = create_async_engine(settings.database_url)
    try:
        async with fresh_engine.connect() as conn:
            project_row = (
                await conn.execute(text("SELECT id, name FROM projects WHERE id = :id"), {"id": project_id})
            ).first()
            model_row = (
                await conn.execute(
                    text("SELECT project_id, version FROM system_model_versions WHERE project_id = :id"),
                    {"id": project_id},
                )
            ).first()
    finally:
        await fresh_engine.dispose()

    assert project_row is not None
    assert project_row.name == "Payments Platform"
    assert model_row is not None
    assert model_row.version == 1


def test_restore_of_a_missing_archive_raises_a_clear_error(tmp_path):
    settings = get_settings()
    with pytest.raises(BackupError, match="not found"):
        restore_backup(settings, tmp_path / "does-not-exist.tar.gz")


def test_backup_archive_never_contains_a_path_traversal_member(tmp_path):
    """A structural guarantee: restore_backup extracts with tarfile's
    `"data"` filter, which rejects any member whose name would resolve
    outside the destination directory (e.g. `../../etc/passwd`)."""
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    malicious_archive = tmp_path / "malicious.tar.gz"
    with tarfile.open(malicious_archive, "w:gz") as tar:
        info = tarfile.TarInfo(name="data/../../evil.txt")
        payload = b"pwned"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    with pytest.raises(tarfile.OutsideDestinationError):
        restore_backup(settings, malicious_archive)
