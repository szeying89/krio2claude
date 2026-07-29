from app.models.enums import RunStatus, StageStatus


class IllegalTransitionError(Exception):
    def __init__(self, current: object, target: object) -> None:
        self.current = current
        self.target = target
        super().__init__(f"illegal transition: {current} -> {target}")


# Both states are terminal: complete and failed accept no further transitions.
RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.QUEUED: frozenset({RunStatus.RUNNING, RunStatus.FAILED}),
    RunStatus.RUNNING: frozenset(
        {RunStatus.NEEDS_INPUT, RunStatus.COMPLETE, RunStatus.FAILED}
    ),
    RunStatus.NEEDS_INPUT: frozenset({RunStatus.RUNNING, RunStatus.FAILED}),
    RunStatus.COMPLETE: frozenset(),
    RunStatus.FAILED: frozenset(),
}

STAGE_TRANSITIONS: dict[StageStatus, frozenset[StageStatus]] = {
    StageStatus.PENDING: frozenset({StageStatus.RUNNING, StageStatus.FAILED}),
    StageStatus.RUNNING: frozenset(
        {StageStatus.NEEDS_INPUT, StageStatus.COMPLETE, StageStatus.FAILED}
    ),
    StageStatus.NEEDS_INPUT: frozenset({StageStatus.RUNNING, StageStatus.FAILED}),
    StageStatus.COMPLETE: frozenset(),
    StageStatus.FAILED: frozenset(),
}


def validate_run_transition(current: RunStatus, target: RunStatus) -> None:
    if target not in RUN_TRANSITIONS.get(current, frozenset()):
        raise IllegalTransitionError(current, target)


def validate_stage_transition(current: StageStatus, target: StageStatus) -> None:
    if target not in STAGE_TRANSITIONS.get(current, frozenset()):
        raise IllegalTransitionError(current, target)
