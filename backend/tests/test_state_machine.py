import pytest

from app.models.enums import RunStatus, StageStatus
from app.orchestrator.state_machine import (
    IllegalTransitionError,
    validate_run_transition,
    validate_stage_transition,
)

LEGAL_RUN_TRANSITIONS = [
    (RunStatus.QUEUED, RunStatus.RUNNING),
    (RunStatus.QUEUED, RunStatus.FAILED),
    (RunStatus.RUNNING, RunStatus.NEEDS_INPUT),
    (RunStatus.RUNNING, RunStatus.COMPLETE),
    (RunStatus.RUNNING, RunStatus.FAILED),
    (RunStatus.NEEDS_INPUT, RunStatus.RUNNING),
    (RunStatus.NEEDS_INPUT, RunStatus.FAILED),
]

ILLEGAL_RUN_TRANSITIONS = [
    (RunStatus.QUEUED, RunStatus.COMPLETE),
    (RunStatus.QUEUED, RunStatus.NEEDS_INPUT),
    (RunStatus.RUNNING, RunStatus.QUEUED),
    (RunStatus.NEEDS_INPUT, RunStatus.COMPLETE),
    (RunStatus.NEEDS_INPUT, RunStatus.QUEUED),
    (RunStatus.COMPLETE, RunStatus.RUNNING),
    (RunStatus.COMPLETE, RunStatus.FAILED),
    (RunStatus.COMPLETE, RunStatus.QUEUED),
    (RunStatus.COMPLETE, RunStatus.NEEDS_INPUT),
    (RunStatus.FAILED, RunStatus.RUNNING),
    (RunStatus.FAILED, RunStatus.QUEUED),
    (RunStatus.FAILED, RunStatus.COMPLETE),
    (RunStatus.FAILED, RunStatus.NEEDS_INPUT),
]


@pytest.mark.parametrize("current,target", LEGAL_RUN_TRANSITIONS)
def test_legal_run_transitions_allowed(current, target):
    validate_run_transition(current, target)  # must not raise


@pytest.mark.parametrize("current,target", ILLEGAL_RUN_TRANSITIONS)
def test_illegal_run_transitions_rejected(current, target):
    with pytest.raises(IllegalTransitionError):
        validate_run_transition(current, target)


def test_all_run_status_pairs_covered():
    all_pairs = {(c, t) for c in RunStatus for t in RunStatus if c != t}
    covered = set(LEGAL_RUN_TRANSITIONS) | set(ILLEGAL_RUN_TRANSITIONS)
    assert all_pairs == covered, all_pairs - covered


LEGAL_STAGE_TRANSITIONS = [
    (StageStatus.PENDING, StageStatus.RUNNING),
    (StageStatus.PENDING, StageStatus.FAILED),
    (StageStatus.RUNNING, StageStatus.NEEDS_INPUT),
    (StageStatus.RUNNING, StageStatus.COMPLETE),
    (StageStatus.RUNNING, StageStatus.FAILED),
    (StageStatus.NEEDS_INPUT, StageStatus.RUNNING),
    (StageStatus.NEEDS_INPUT, StageStatus.FAILED),
]

ILLEGAL_STAGE_TRANSITIONS = [
    (StageStatus.PENDING, StageStatus.COMPLETE),
    (StageStatus.PENDING, StageStatus.NEEDS_INPUT),
    (StageStatus.COMPLETE, StageStatus.RUNNING),
    (StageStatus.FAILED, StageStatus.RUNNING),
]


@pytest.mark.parametrize("current,target", LEGAL_STAGE_TRANSITIONS)
def test_legal_stage_transitions_allowed(current, target):
    validate_stage_transition(current, target)


@pytest.mark.parametrize("current,target", ILLEGAL_STAGE_TRANSITIONS)
def test_illegal_stage_transitions_rejected(current, target):
    with pytest.raises(IllegalTransitionError):
        validate_stage_transition(current, target)
