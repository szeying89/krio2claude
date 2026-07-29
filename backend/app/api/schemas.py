from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import RunStatus, StageStatus


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
