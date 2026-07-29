from fastapi import APIRouter, Depends, HTTPException, UploadFile

from app.api.deps import get_project_service
from app.api.schemas import (
    CreateProjectRequest,
    DesignDocumentOut,
    ProjectOut,
    UpdateProjectRequest,
)
from app.services.project_service import (
    DocumentNotFoundError,
    ProjectNotFoundError,
    ProjectService,
)
from app.services.text_extraction import TextExtractionError
from app.services.upload_validation import UploadValidationError

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectOut)
async def create_project(
    body: CreateProjectRequest, service: ProjectService = Depends(get_project_service)
) -> ProjectOut:
    project = await service.create_project(**body.model_dump())
    return ProjectOut.model_validate(project)


@router.get("", response_model=list[ProjectOut])
async def list_projects(service: ProjectService = Depends(get_project_service)) -> list[ProjectOut]:
    projects = await service.list_projects()
    return [ProjectOut.model_validate(p) for p in projects]


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: str, service: ProjectService = Depends(get_project_service)
) -> ProjectOut:
    try:
        project = await service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return ProjectOut.model_validate(project)


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: str,
    body: UpdateProjectRequest,
    service: ProjectService = Depends(get_project_service),
) -> ProjectOut:
    try:
        project = await service.update_project(
            project_id, **body.model_dump(exclude_unset=True)
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return ProjectOut.model_validate(project)


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: str, service: ProjectService = Depends(get_project_service)
) -> None:
    try:
        await service.delete_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc


@router.post("/{project_id}/documents", response_model=DesignDocumentOut)
async def upload_document(
    project_id: str,
    file: UploadFile,
    service: ProjectService = Depends(get_project_service),
) -> DesignDocumentOut:
    content = await file.read()
    try:
        document = await service.ingest_document(project_id, file.filename or "upload", content)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except UploadValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TextExtractionError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return DesignDocumentOut.model_validate(document)


@router.get("/{project_id}/documents/{document_id}", response_model=DesignDocumentOut)
async def get_document(
    project_id: str, document_id: str, service: ProjectService = Depends(get_project_service)
) -> DesignDocumentOut:
    try:
        document = await service.get_document(project_id, document_id)
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail="document not found") from exc
    return DesignDocumentOut.model_validate(document)
