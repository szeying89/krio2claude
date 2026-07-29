from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.models.enums import RunStatus, StageStatus
from app.models.run import Run, RunStage
from app.orchestrator.events import EventBus
from app.orchestrator.state_machine import (
    validate_run_transition,
    validate_stage_transition,
)


class RunNotFoundError(Exception):
    pass


class StageNotFoundError(Exception):
    pass


class RunService:
    """Owns run/stage persistence and legal state transitions.

    This is the deterministic control-plane surface of the orchestrator
    (see IMPLEMENTATION_PLAN.md — "Orchestrator, Agent, and Service
    architecture"). It never calls an LLM or agent itself; agents are wired
    in via Task 1b's AgentInvocation contract and call back into this
    service to record stage progress.
    """

    def __init__(self, session: AsyncSession, event_bus: EventBus, settings: Settings) -> None:
        self.session = session
        self.event_bus = event_bus
        self.settings = settings

    async def create_run(
        self,
        stage_names: list[str],
        project_name: str | None = None,
        parent_run_id: str | None = None,
    ) -> Run:
        run = Run(
            status=RunStatus.QUEUED, project_name=project_name, parent_run_id=parent_run_id
        )
        self.session.add(run)
        await self.session.flush()

        for index, name in enumerate(stage_names):
            self.session.add(
                RunStage(
                    run_id=run.id,
                    sequence_index=index,
                    name=name,
                    status=StageStatus.PENDING,
                )
            )
        await self.session.commit()
        (self.settings.runs_dir / run.id).mkdir(parents=True, exist_ok=True)
        return await self.get_run(run.id)

    async def get_run(self, run_id: str) -> Run:
        result = await self.session.execute(
            select(Run).where(Run.id == run_id).options(selectinload(Run.stages))
        )
        run = result.scalar_one_or_none()
        if run is None:
            raise RunNotFoundError(run_id)
        return run

    async def _get_stage(self, run_id: str, stage_id: str) -> RunStage:
        result = await self.session.execute(
            select(RunStage).where(RunStage.id == stage_id, RunStage.run_id == run_id)
        )
        stage = result.scalar_one_or_none()
        if stage is None:
            raise StageNotFoundError(stage_id)
        return stage

    async def transition_run(self, run_id: str, target: RunStatus) -> Run:
        run = await self.get_run(run_id)
        validate_run_transition(run.status, target)
        run.status = target
        await self.session.commit()
        await self.event_bus.publish(
            run_id,
            {
                "type": "run_status",
                "run_id": run_id,
                "status": target.value,
                "at": datetime.now(UTC).isoformat(),
            },
        )
        return await self.get_run(run_id)

    async def transition_stage(
        self, run_id: str, stage_id: str, target: StageStatus, error: str | None = None
    ) -> RunStage:
        stage = await self._get_stage(run_id, stage_id)
        validate_stage_transition(stage.status, target)
        stage.status = target
        now = datetime.now(UTC)
        if target == StageStatus.RUNNING and stage.started_at is None:
            stage.started_at = now
        if target in (StageStatus.COMPLETE, StageStatus.FAILED):
            stage.completed_at = now
        if error is not None:
            stage.error = error
        await self.session.commit()
        await self.event_bus.publish(
            run_id,
            {
                "type": "stage_status",
                "run_id": run_id,
                "stage_id": stage_id,
                "stage_name": stage.name,
                "status": target.value,
                "at": now.isoformat(),
            },
        )
        return stage
