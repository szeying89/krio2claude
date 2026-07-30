"""Persistence for Task 19's `ThreatModelRevision` chain. Deliberately
thin: gathering everything a snapshot needs (system model, KB/CRI
pins, intel articles) is API-layer composition (mirroring
`app/api/gap_context.py`'s role for Tasks 15/16/17), not this service's
job — this service only stores and retrieves already-computed
`RevisionSnapshot`s against a project, immutably, exactly like
`ProjectSystemModelService` does for system-model versions.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.revision import ThreatModelRevision
from app.services.revision.models import RevisionSnapshot


class ProjectNotFoundError(Exception):
    pass


class RevisionNotFoundError(Exception):
    pass


class ProjectRevisionService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _get_project(self, project_id: str) -> Project:
        result = await self.session.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(project_id)
        return project

    async def create_revision(
        self,
        project_id: str,
        parent_revision_id: str | None,
        system_model_version: int,
        kb_snapshot_hash: str | None,
        cri_snapshot_hash: str | None,
        intel_article_hashes: list[str],
        snapshot: RevisionSnapshot,
    ) -> ThreatModelRevision:
        await self._get_project(project_id)
        record = ThreatModelRevision(
            project_id=project_id,
            parent_revision_id=parent_revision_id,
            system_model_version=system_model_version,
            kb_snapshot_hash=kb_snapshot_hash,
            cri_snapshot_hash=cri_snapshot_hash,
            intel_article_hashes=intel_article_hashes,
            snapshot=snapshot.to_dict(),
            created_at=datetime.now(UTC),
        )
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        return record

    async def get_revision(self, project_id: str, revision_id: str) -> ThreatModelRevision:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(ThreatModelRevision).where(
                ThreatModelRevision.id == revision_id, ThreatModelRevision.project_id == project_id
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            raise RevisionNotFoundError(revision_id)
        return record

    async def get_latest_revision(self, project_id: str) -> ThreatModelRevision | None:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(ThreatModelRevision)
            .where(ThreatModelRevision.project_id == project_id)
            .order_by(ThreatModelRevision.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def list_revisions(self, project_id: str) -> list[ThreatModelRevision]:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(ThreatModelRevision)
            .where(ThreatModelRevision.project_id == project_id)
            .order_by(ThreatModelRevision.created_at.asc())
        )
        return list(result.scalars().all())
