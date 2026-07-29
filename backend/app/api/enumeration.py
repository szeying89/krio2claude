from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_system_model_service
from app.services.enumeration.matrix import EnumerationResult, build_enumeration_result
from app.services.enumeration.ruleset import load_ruleset
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)

router = APIRouter(prefix="/projects", tags=["enumeration"])

_RULESET = load_ruleset()


class CandidateThreatOut(BaseModel):
    id: str
    element_id: str
    element_kind: str
    framework: str
    category: str
    ruleset_version: str


class ElementMatrixRowOut(BaseModel):
    element_id: str
    element_name: str
    element_kind: str
    stride_categories: list[str]
    linddun_categories: list[str]


class EnumerationResultOut(BaseModel):
    ruleset_version: str
    linddun_present: bool
    matrix: list[ElementMatrixRowOut]
    candidates: list[CandidateThreatOut]


def _result_out(result: EnumerationResult) -> EnumerationResultOut:
    return EnumerationResultOut(
        ruleset_version=result.ruleset_version,
        linddun_present=result.linddun_present,
        matrix=[
            ElementMatrixRowOut(
                element_id=row.element_id,
                element_name=row.element_name,
                element_kind=row.element_kind,
                stride_categories=list(row.stride_categories),
                linddun_categories=list(row.linddun_categories),
            )
            for row in result.matrix
        ],
        candidates=[
            CandidateThreatOut(
                id=c.id,
                element_id=c.element_id,
                element_kind=c.element_kind,
                framework=c.framework,
                category=c.category,
                ruleset_version=c.ruleset_version,
            )
            for c in result.candidates
        ],
    )


@router.get("/{project_id}/system-model/threats", response_model=EnumerationResultOut)
async def get_latest_enumeration(
    project_id: str, model_service: ProjectSystemModelService = Depends(get_system_model_service)
) -> EnumerationResultOut:
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return _result_out(build_enumeration_result(model, _RULESET))


@router.get(
    "/{project_id}/system-model/versions/{version}/threats", response_model=EnumerationResultOut
)
async def get_enumeration_for_version(
    project_id: str,
    version: int,
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> EnumerationResultOut:
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    return _result_out(build_enumeration_result(model, _RULESET))
