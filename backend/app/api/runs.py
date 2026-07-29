import json

from fastapi import APIRouter, Depends, HTTPException
from sse_starlette.sse import EventSourceResponse

from app.api.deps import get_bus, get_run_service
from app.api.schemas import (
    CreateRunRequest,
    RunOut,
    TransitionRunRequest,
    TransitionStageRequest,
)
from app.orchestrator.events import EventBus
from app.orchestrator.run_service import (
    RunNotFoundError,
    RunService,
    StageNotFoundError,
)
from app.orchestrator.state_machine import IllegalTransitionError

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunOut)
async def create_run(
    body: CreateRunRequest, service: RunService = Depends(get_run_service)
) -> RunOut:
    run = await service.create_run(
        stage_names=body.stage_names,
        project_name=body.project_name,
        parent_run_id=body.parent_run_id,
    )
    return RunOut.model_validate(run)


@router.get("/{run_id}", response_model=RunOut)
async def get_run(run_id: str, service: RunService = Depends(get_run_service)) -> RunOut:
    try:
        run = await service.get_run(run_id)
    except RunNotFoundError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    return RunOut.model_validate(run)


@router.post("/{run_id}/transition", response_model=RunOut)
async def transition_run(
    run_id: str, body: TransitionRunRequest, service: RunService = Depends(get_run_service)
) -> RunOut:
    try:
        run = await service.transition_run(run_id, body.status)
    except RunNotFoundError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    except IllegalTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return RunOut.model_validate(run)


@router.post("/{run_id}/stages/{stage_id}/transition")
async def transition_stage(
    run_id: str,
    stage_id: str,
    body: TransitionStageRequest,
    service: RunService = Depends(get_run_service),
) -> dict:
    try:
        stage = await service.transition_stage(run_id, stage_id, body.status, body.error)
    except (RunNotFoundError, StageNotFoundError) as exc:
        raise HTTPException(status_code=404, detail="not found") from exc
    except IllegalTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "id": stage.id,
        "name": stage.name,
        "status": stage.status.value,
    }


@router.get("/{run_id}/events")
async def stream_run_events(run_id: str, bus: EventBus = Depends(get_bus)) -> EventSourceResponse:
    async def event_generator():
        async for event in bus.stream(run_id):
            yield {"event": event["type"], "data": json.dumps(event)}

    return EventSourceResponse(event_generator())
