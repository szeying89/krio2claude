from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.models.project import Project
from app.models.systemmodel import SystemModelVersion
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.modelbuilding.agent import documents_input_for_project, run_model_building
from app.services.systemmodel.edits import ModelEdits, apply_edits
from app.services.systemmodel.freeze import freeze_draft
from app.services.systemmodel.models import SystemModel
from app.services.systemmodel.otm import from_otm, to_otm
from app.services.systemmodel.out_of_scope import detect_out_of_scope
from app.services.systemmodel.versioning import diff_models


class ProjectNotFoundError(Exception):
    pass


class SystemModelNotFoundError(Exception):
    pass


class ProjectSystemModelService:
    """Owns the version chain of a project's frozen `SystemModel`s: the
    freeze pipeline (draft -> out-of-scope detection -> version N+1,
    diffed against N), user edits (also version N+1, diffed), and lookups.
    Every version is stored as its own OTM document (see
    `app/models/systemmodel.py`), never mutated once written.
    """

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    async def _get_project(self, project_id: str) -> Project:
        result = await self.session.execute(
            select(Project)
            .where(Project.id == project_id)
            .options(selectinload(Project.documents))
        )
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(project_id)
        return project

    async def _latest_row(self, project_id: str) -> SystemModelVersion | None:
        result = await self.session.execute(
            select(SystemModelVersion)
            .where(SystemModelVersion.project_id == project_id)
            .order_by(SystemModelVersion.version.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def _next_version_number(self, project_id: str) -> int:
        result = await self.session.execute(
            select(func.max(SystemModelVersion.version)).where(
                SystemModelVersion.project_id == project_id
            )
        )
        current_max = result.scalar_one_or_none()
        return 1 if current_max is None else current_max + 1

    async def _persist(self, project_id: str, model: SystemModel) -> SystemModelVersion:
        row = SystemModelVersion(
            project_id=project_id, version=model.version, otm_document=to_otm(model)
        )
        self.session.add(row)
        await self.session.commit()
        await self.session.refresh(row)
        return row

    async def freeze(
        self, project_id: str, gateway: LLMGateway, params: CompletionParams
    ) -> SystemModel:
        project = await self._get_project(project_id)
        documents = documents_input_for_project(project)
        draft = run_model_building(gateway, params, documents)

        model = freeze_draft(draft, model_id=project_id)
        model.out_of_scope = detect_out_of_scope(model.components)
        freeze_notes = list(model.change_summary)

        previous_row = await self._latest_row(project_id)
        previous_model = from_otm(previous_row.otm_document) if previous_row is not None else None
        model.version = await self._next_version_number(project_id)
        model.parent_version = previous_model.version if previous_model is not None else None
        model.change_summary = freeze_notes + diff_models(previous_model, model)

        await self._persist(project_id, model)
        return model

    async def apply_user_edits(self, project_id: str, edits: ModelEdits) -> SystemModel:
        await self._get_project(project_id)
        previous_row = await self._latest_row(project_id)
        if previous_row is None:
            raise SystemModelNotFoundError(project_id)
        previous_model = from_otm(previous_row.otm_document)

        updated = apply_edits(previous_model, edits)
        updated.version = await self._next_version_number(project_id)
        updated.parent_version = previous_model.version
        updated.change_summary = diff_models(previous_model, updated)

        await self._persist(project_id, updated)
        return updated

    async def get_latest(self, project_id: str) -> SystemModel:
        await self._get_project(project_id)
        row = await self._latest_row(project_id)
        if row is None:
            raise SystemModelNotFoundError(project_id)
        return from_otm(row.otm_document)

    async def get_version(self, project_id: str, version: int) -> SystemModel:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(SystemModelVersion).where(
                SystemModelVersion.project_id == project_id, SystemModelVersion.version == version
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise SystemModelNotFoundError(f"{project_id} v{version}")
        return from_otm(row.otm_document)

    async def list_versions(self, project_id: str) -> list[int]:
        await self._get_project(project_id)
        result = await self.session.execute(
            select(SystemModelVersion.version)
            .where(SystemModelVersion.project_id == project_id)
            .order_by(SystemModelVersion.version)
        )
        return list(result.scalars().all())
