from fastapi import APIRouter, Depends, HTTPException, UploadFile

from app.api.deps import get_project_cri_service
from app.api.schemas import ImpactTieringOut, ImpactTieringRequest
from app.services.cri.db_service import (
    CRIProfileNotUploadedError,
    ProjectCRIService,
    ProjectNotFoundError,
)
from app.services.cri.tiering import QuestionAnswer, TieringError
from app.services.cri.workbook_parser import CRIWorkbookParseError

router = APIRouter(prefix="/projects/{project_id}", tags=["cri"])


@router.post("/cri-profile")
async def upload_cri_profile(
    project_id: str,
    file: UploadFile,
    service: ProjectCRIService = Depends(get_project_cri_service),
) -> dict:
    content = await file.read()
    try:
        return await service.upload_cri_profile(project_id, file.filename or "cri-profile.xlsx", content)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except CRIWorkbookParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/cri-profile")
async def get_cri_profile(
    project_id: str, service: ProjectCRIService = Depends(get_project_cri_service)
) -> dict:
    try:
        return await service.get_manifest(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except CRIProfileNotUploadedError as exc:
        raise HTTPException(
            status_code=404, detail="no CRI profile uploaded for this project"
        ) from exc


@router.get("/cri-profile/statements")
async def get_cri_statements(
    project_id: str,
    tier: int | None = None,
    service: ProjectCRIService = Depends(get_project_cri_service),
) -> list[dict]:
    try:
        return await service.get_statements(project_id, tier=tier)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except CRIProfileNotUploadedError as exc:
        raise HTTPException(
            status_code=404, detail="no CRI profile uploaded for this project"
        ) from exc


@router.post("/impact-tiering", response_model=ImpactTieringOut)
async def submit_impact_tiering(
    project_id: str,
    body: ImpactTieringRequest,
    service: ProjectCRIService = Depends(get_project_cri_service),
) -> ImpactTieringOut:
    answers = [QuestionAnswer(a.question_id, a.answer, a.justification) for a in body.answers]
    try:
        record = await service.compute_tiering(project_id, answers)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except TieringError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return ImpactTieringOut.model_validate(record)


@router.get("/impact-tiering", response_model=ImpactTieringOut)
async def get_impact_tiering(
    project_id: str, service: ProjectCRIService = Depends(get_project_cri_service)
) -> ImpactTieringOut:
    try:
        record = await service.get_tiering(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    if record is None:
        raise HTTPException(status_code=404, detail="impact tiering not yet computed")
    return ImpactTieringOut.model_validate(record)
