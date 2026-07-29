import io
import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.project import ImpactTiering, Project
from app.services.cri.ingestion_service import CRIIngestionService
from app.services.cri.snapshot import read_manifest as read_cri_manifest
from app.services.cri.tiering import QuestionAnswer, compute_tier
from app.services.kb.snapshot import read_manifest as read_kb_manifest


class ProjectNotFoundError(Exception):
    pass


class CRIProfileNotUploadedError(Exception):
    """Missing-CRI mode: no CRI workbook has been uploaded for this project."""


def _latest_kb_snapshot_dir(kb_dir: Path) -> Path | None:
    if not kb_dir.exists():
        return None
    candidates = [d for d in kb_dir.iterdir() if d.is_dir() and not d.name.startswith(".tmp-")]
    if not candidates:
        return None
    return max(candidates, key=lambda d: read_kb_manifest(d)["fetched_at"])


class ProjectCRIService:
    """Associates a project with a content-hashed CRI snapshot and its
    computed Impact Tiering result. Mirrors ProjectService's pattern."""

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    async def _get_project(self, project_id: str) -> Project:
        result = await self.session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(project_id)
        return project

    async def upload_cri_profile(
        self, project_id: str, filename: str, content: bytes
    ) -> dict[str, Any]:
        project = await self._get_project(project_id)

        kb_snapshot_dir = _latest_kb_snapshot_dir(self.settings.kb_dir)
        ingestion = CRIIngestionService(self.settings.cri_dir)
        snapshot_dir = ingestion.ingest(
            io.BytesIO(content),
            filename,
            fetched_at=datetime.now(UTC).isoformat(),
            kb_snapshot_dir=kb_snapshot_dir,
        )

        project.cri_snapshot_hash = snapshot_dir.name
        await self.session.commit()
        return read_cri_manifest(snapshot_dir)

    async def get_manifest(self, project_id: str) -> dict[str, Any]:
        project = await self._get_project(project_id)
        if not project.cri_snapshot_hash:
            raise CRIProfileNotUploadedError(project_id)
        snapshot_dir = self.settings.cri_dir / project.cri_snapshot_hash
        return read_cri_manifest(snapshot_dir)

    async def get_statements(
        self, project_id: str, tier: int | None = None
    ) -> list[dict[str, Any]]:
        project = await self._get_project(project_id)
        if not project.cri_snapshot_hash:
            raise CRIProfileNotUploadedError(project_id)
        snapshot_dir = self.settings.cri_dir / project.cri_snapshot_hash
        statements = json.loads((snapshot_dir / "statements.json").read_text())
        if tier is not None:
            statements = [s for s in statements if tier in s["applicable_tiers"]]
        return statements

    async def compute_tiering(
        self, project_id: str, answers: list[QuestionAnswer]
    ) -> ImpactTiering:
        await self._get_project(project_id)  # raises ProjectNotFoundError if missing
        result = compute_tier(answers)

        existing = await self.session.get(ImpactTiering, project_id)
        answers_json = [asdict(a) for a in result.answers]
        if existing is not None:
            existing.tier = result.tier
            existing.triggering_question_id = result.triggering_question_id
            existing.answers = answers_json
            existing.computed_at = datetime.now(UTC)
            record = existing
        else:
            record = ImpactTiering(
                project_id=project_id,
                tier=result.tier,
                triggering_question_id=result.triggering_question_id,
                answers=answers_json,
            )
            self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record

    async def get_tiering(self, project_id: str) -> ImpactTiering | None:
        await self._get_project(project_id)
        return await self.session.get(ImpactTiering, project_id)
