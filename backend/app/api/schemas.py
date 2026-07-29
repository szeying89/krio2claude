from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import BusinessCriticality, RunStatus, StageStatus, SystemClass


class RunStageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sequence_index: int
    name: str
    status: StageStatus
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: RunStatus
    parent_run_id: str | None
    project_name: str | None
    created_at: datetime
    updated_at: datetime
    stages: list[RunStageOut]


class CreateRunRequest(BaseModel):
    stage_names: list[str]
    project_name: str | None = None
    parent_run_id: str | None = None


class TransitionRunRequest(BaseModel):
    status: RunStatus


class TransitionStageRequest(BaseModel):
    status: StageStatus
    error: str | None = None


class DesignDocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    filename: str
    content_type: str
    sha256: str
    size_bytes: int
    extracted_prose: str
    mermaid_blocks: list[dict[str, Any]]
    created_at: datetime


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    business_criticality: BusinessCriticality
    system_class: SystemClass
    data_classifications: list[str]
    compliance_regimes: list[str]
    scope_statements: list[str]
    declared_controls: list[str]
    atlas_enabled: bool
    created_at: datetime
    updated_at: datetime
    documents: list[DesignDocumentOut]


class CreateProjectRequest(BaseModel):
    name: str
    business_criticality: BusinessCriticality
    system_class: SystemClass
    data_classifications: list[str] = []
    compliance_regimes: list[str] = []
    scope_statements: list[str] = []
    declared_controls: list[str] = []


class UpdateProjectRequest(BaseModel):
    name: str | None = None
    business_criticality: BusinessCriticality | None = None
    system_class: SystemClass | None = None
    data_classifications: list[str] | None = None
    compliance_regimes: list[str] | None = None
    scope_statements: list[str] | None = None
    declared_controls: list[str] | None = None


class ImpactTieringAnswerIn(BaseModel):
    question_id: str
    answer: bool
    justification: str = ""


class ImpactTieringRequest(BaseModel):
    answers: list[ImpactTieringAnswerIn]


class ImpactTieringOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    project_id: str
    tier: int
    triggering_question_id: str | None
    answers: list[dict[str, Any]]
    computed_at: datetime


class RetrievalResultOut(BaseModel):
    doc_id: str
    fused_score: float
    bm25_rank: int | None
    dense_rank: int | None
    snippet: str
    metadata: dict[str, Any]
