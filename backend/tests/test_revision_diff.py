import pytest

from app.services.revision.diff import compute_diff
from app.services.revision.models import (
    AdjudicationSummary,
    CSFFunctionSummary,
    PathSummary,
    RevisionSnapshot,
    ThreatLandscapeCurrency,
)

CURRENCY = ThreatLandscapeCurrency(
    kb_fetched_at="2026-01-01T00:00:00Z", cri_fetched_at=None, intel_article_count=0, latest_intel_fetched_at=None
)


def _snapshot(paths=(), adjudications=(), rejection_count=0, risk_total_score=0.0, csf_rollup=(), confidence=1.0):
    return RevisionSnapshot(
        paths=paths, adjudications=adjudications, rejection_count=rejection_count,
        risk_total_score=risk_total_score, csf_rollup=csf_rollup, confidence=confidence, currency=CURRENCY,
    )


def test_identical_snapshots_produce_a_zero_change_diff():
    snapshot = _snapshot(
        paths=(PathSummary("p1", "a", "b", ("T1",), 0.5),),
        adjudications=(AdjudicationSummary("c1", "applicable", 1.0),),
        risk_total_score=1.0,
    )
    diff = compute_diff(snapshot, snapshot)
    assert diff.new_path_ids == ()
    assert diff.removed_path_ids == ()
    assert diff.changed_paths == ()
    assert diff.reopened_adjudication_ids == ()
    assert diff.risk_score_delta == 0.0
    assert diff.confidence_delta == 0.0


def test_new_and_removed_paths_are_detected():
    parent = _snapshot(paths=(PathSummary("p1", "a", "b", ("T1",), 0.5),))
    child = _snapshot(paths=(PathSummary("p2", "a", "c", ("T2",), 0.3),))
    diff = compute_diff(parent, child)
    assert diff.new_path_ids == ("p2",)
    assert diff.removed_path_ids == ("p1",)


def test_changed_path_likelihood_reported_with_correct_delta():
    parent = _snapshot(paths=(PathSummary("p1", "a", "b", ("T1",), 0.2),))
    child = _snapshot(paths=(PathSummary("p1", "a", "b", ("T1",), 0.6),))
    diff = compute_diff(parent, child)
    assert len(diff.changed_paths) == 1
    change = diff.changed_paths[0]
    assert change.previous_likelihood == 0.2
    assert change.new_likelihood == 0.6
    assert change.delta == pytest.approx(0.4)


def test_reopened_adjudications_detected_and_nothing_else():
    parent = _snapshot(
        adjudications=(
            AdjudicationSummary("c1", "not_applicable", 0.5),
            AdjudicationSummary("c2", "applicable", 0.9),
            AdjudicationSummary("c3", "not_applicable", 0.5),
        )
    )
    child = _snapshot(
        adjudications=(
            AdjudicationSummary("c1", "applicable", 0.9),  # reopened
            AdjudicationSummary("c2", "applicable", 0.9),  # already applicable, not "reopened"
            AdjudicationSummary("c3", "not_applicable", 0.5),  # stays not_applicable
        )
    )
    diff = compute_diff(parent, child)
    assert diff.reopened_adjudication_ids == ("c1",)


def test_applicable_to_not_applicable_is_never_reported_as_reopened():
    parent = _snapshot(adjudications=(AdjudicationSummary("c1", "applicable", 0.9),))
    child = _snapshot(adjudications=(AdjudicationSummary("c1", "not_applicable", 0.1),))
    diff = compute_diff(parent, child)
    assert diff.reopened_adjudication_ids == ()


def test_csf_rollup_movement_and_risk_and_confidence_deltas():
    parent = _snapshot(
        csf_rollup=(CSFFunctionSummary("GV", 0.5),), risk_total_score=1.0, confidence=0.8
    )
    child = _snapshot(
        csf_rollup=(CSFFunctionSummary("GV", 0.2), CSFFunctionSummary("PR", 0.9)),
        risk_total_score=1.5, confidence=0.9,
    )
    diff = compute_diff(parent, child)
    gv = next(m for m in diff.csf_rollup_movement if m.function == "GV")
    pr = next(m for m in diff.csf_rollup_movement if m.function == "PR")
    assert gv.previous_density == 0.5
    assert gv.new_density == 0.2
    assert pr.previous_density == 0.0
    assert pr.new_density == 0.9
    assert diff.risk_score_delta == 0.5
    assert round(diff.confidence_delta, 10) == round(0.1, 10)


def test_diff_is_symmetric_under_swap():
    a = _snapshot(
        paths=(PathSummary("p1", "a", "b", ("T1",), 0.2),),
        adjudications=(AdjudicationSummary("c1", "not_applicable", 0.5),),
        risk_total_score=1.0,
        csf_rollup=(CSFFunctionSummary("GV", 0.5),),
        confidence=0.7,
    )
    b = _snapshot(
        paths=(PathSummary("p1", "a", "b", ("T1",), 0.6), PathSummary("p2", "a", "c", ("T2",), 0.4)),
        adjudications=(AdjudicationSummary("c1", "applicable", 0.9),),
        risk_total_score=1.8,
        csf_rollup=(CSFFunctionSummary("GV", 0.2),),
        confidence=0.9,
    )
    forward = compute_diff(a, b)
    backward = compute_diff(b, a)

    assert forward.new_path_ids == backward.removed_path_ids
    assert forward.removed_path_ids == backward.new_path_ids
    assert round(forward.risk_score_delta, 10) == round(-backward.risk_score_delta, 10)
    assert round(forward.confidence_delta, 10) == round(-backward.confidence_delta, 10)
    for fwd_change, bwd_change in zip(forward.changed_paths, backward.changed_paths, strict=True):
        assert fwd_change.path_id == bwd_change.path_id
        assert fwd_change.delta == -bwd_change.delta
    for fwd_move, bwd_move in zip(forward.csf_rollup_movement, backward.csf_rollup_movement, strict=True):
        assert fwd_move.function == bwd_move.function
        assert round(fwd_move.delta, 10) == round(-bwd_move.delta, 10)


def test_diff_is_deterministic_across_repeated_calls():
    parent = _snapshot(paths=(PathSummary("p1", "a", "b", ("T1",), 0.2),))
    child = _snapshot(paths=(PathSummary("p1", "a", "b", ("T1",), 0.6),))
    first = compute_diff(parent, child)
    second = compute_diff(parent, child)
    assert first == second
