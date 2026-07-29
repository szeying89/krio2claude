import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.models.enums import BusinessCriticality, SystemClass
from app.models.project import DesignDocument, Project
from app.services.mermaid_extraction import extract_mermaid_blocks, strip_mermaid_blocks
from app.services.text_extraction import extract_text
from app.services.upload_validation import validate_upload


class ProjectNotFoundError(Exception):
    pass


class DocumentNotFoundError(Exception):
    pass


class ProjectService:
    """Project CRUD and design-document ingestion.

    This is domain logic the Model-Building Agent (Q1) will call as tools
    once agents exist (Task 8+) — see IMPLEMENTATION_PLAN.md's agent/tool
    table. It has no LLM or orchestrator dependency of its own.
    """

    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    async def create_project(
        self,
        name: str,
        business_criticality: BusinessCriticality,
        system_class: SystemClass,
        data_classifications: list[str] | None = None,
        compliance_regimes: list[str] | None = None,
        scope_statements: list[str] | None = None,
        declared_controls: list[str] | None = None,
    ) -> Project:
        project = Project(
            name=name,
            business_criticality=business_criticality,
            system_class=system_class,
            data_classifications=data_classifications or [],
            compliance_regimes=compliance_regimes or [],
            scope_statements=scope_statements or [],
            declared_controls=declared_controls or [],
        )
        self.session.add(project)
        await self.session.commit()
        return await self.get_project(project.id)

    async def get_project(self, project_id: str) -> Project:
        result = await self.session.execute(
            select(Project)
            .where(Project.id == project_id)
            .options(selectinload(Project.documents))
        )
        project = result.scalar_one_or_none()
        if project is None:
            raise ProjectNotFoundError(project_id)
        return project

    async def list_projects(self) -> list[Project]:
        result = await self.session.execute(
            select(Project).options(selectinload(Project.documents)).order_by(Project.created_at)
        )
        return list(result.scalars().all())

    async def update_project(self, project_id: str, **fields: object) -> Project:
        project = await self.get_project(project_id)
        for key, value in fields.items():
            if value is not None:
                setattr(project, key, value)
        await self.session.commit()
        return await self.get_project(project_id)

    async def delete_project(self, project_id: str) -> None:
        project = await self.get_project(project_id)
        await self.session.delete(project)
        await self.session.commit()

    async def ingest_document(
        self, project_id: str, filename: str, content: bytes
    ) -> DesignDocument:
        # Raises ProjectNotFoundError if the project doesn't exist.
        await self.get_project(project_id)

        extension = validate_upload(filename, content, self.settings.max_upload_bytes)
        digest = hashlib.sha256(content).hexdigest()
        text = extract_text(extension, content)
        mermaid_blocks = extract_mermaid_blocks(text)
        prose = strip_mermaid_blocks(text)

        doc_dir = self.settings.projects_dir / project_id / "documents"
        doc_dir.mkdir(parents=True, exist_ok=True)
        storage_path = doc_dir / f"{digest}{extension}"
        storage_path.write_bytes(content)

        document = DesignDocument(
            project_id=project_id,
            filename=filename,
            content_type=extension,
            sha256=digest,
            size_bytes=len(content),
            storage_path=str(storage_path),
            extracted_prose=prose,
            mermaid_blocks=[
                {
                    "index": block.index,
                    "source": block.source,
                    "start_line": block.start_line,
                    "end_line": block.end_line,
                }
                for block in mermaid_blocks
            ],
        )
        self.session.add(document)
        await self.session.commit()
        await self.session.refresh(document)
        return document

    async def get_document(self, project_id: str, document_id: str) -> DesignDocument:
        result = await self.session.execute(
            select(DesignDocument).where(
                DesignDocument.id == document_id, DesignDocument.project_id == project_id
            )
        )
        document = result.scalar_one_or_none()
        if document is None:
            raise DocumentNotFoundError(document_id)
        return document
