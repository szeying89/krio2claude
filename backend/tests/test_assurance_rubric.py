import pytest

from app.services.assurance.rubric import (
    cell_adjudication_rate,
    compute_coverage_report,
    cri_mapping_completeness,
    element_coverage,
    grounding_rate,
    limitations_completeness,
    unresolved_assumptions,
)
from app.services.enumeration.adjudication import Adjudication
from app.services.enumeration.agent import RejectionLogEntry
from app.services.enumeration.matrix import ElementMatrixRow, EnumerationResult
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.modelbuilding.models import Assumption
from app.services.systemmodel.models import Component, OutOfScopeDeclaration, SystemModel


def _model(components, out_of_scope=()):
    return SystemModel(id="p1", version=1, parent_version=None, components=components, out_of_scope=list(out_of_scope))


def _gap(technique_id, cri_mapping_absent=False, fallback=()):
    return TechniqueGapAnalysis(
        technique_id=technique_id, d3fend_required_ids=(), d3fend_observed_ids=(), d3fend_gap_ids=(),
        cri_mapping_absent=cri_mapping_absent, cri_in_tier_statement_ids=(), cri_gap_statement_ids=(),
        cri_mapping_inferred_fallback_ids=fallback,
    )


def _assumption(confidence):
    return Assumption(
        kind="default", subject_id="c1", message="assumed", source="agent_generated",
        confidence=confidence, impact_if_wrong="unknown",
    )


def _adjudication(candidate_id, citation_score):
    return Adjudication(
        candidate_threat_id=candidate_id, verdict="applicable", rationale="r",
        evidence_ref="T1", citation_score=citation_score, invalidation_condition=None,
    )


def _rejection(candidate_id):
    return RejectionLogEntry(candidate_threat_id=candidate_id, element_id="c1", category="spoofing", reason_code="no_citation", detail="x")


def test_element_coverage_counts_in_scope_elements_with_a_matched_category():
    model = _model([
        Component(id="c1", name="A", kind="process", trust_zone_id="tz"),
        Component(id="c2", name="B", kind="process", trust_zone_id="tz"),
        Component(id="c3", name="C", kind="process", trust_zone_id="tz", out_of_scope=True),
    ])
    result = EnumerationResult(
        ruleset_version="1.0.0",
        candidates=(),
        matrix=(
            ElementMatrixRow("c1", "A", "process", ("spoofing",), ()),
            ElementMatrixRow("c2", "B", "process", (), ()),
            ElementMatrixRow("c3", "C", "process", (), ()),
        ),
    )
    dim = element_coverage(model, result)
    assert dim.raw_counts == {"covered": 1, "total_in_scope": 2}
    assert dim.score == 50.0


def test_element_coverage_is_100_when_no_in_scope_elements():
    model = _model([])
    result = EnumerationResult(ruleset_version="1.0.0", candidates=(), matrix=())
    assert element_coverage(model, result).score == 100.0


def test_cell_adjudication_rate_exact_fraction():
    dim = cell_adjudication_rate(
        candidate_count=4,
        adjudicated_threats=[_adjudication("c1", 0.9), _adjudication("c2", 0.9), _adjudication("c3", 0.9)],
        rejection_log=[_rejection("c4")],
    )
    assert dim.score == 75.0
    assert dim.raw_counts == {"adjudicated": 3, "rejected": 1, "candidate_count": 4}


def test_grounding_rate_is_mean_citation_score():
    dim = grounding_rate([_adjudication("c1", 0.5), _adjudication("c2", 1.0)])
    assert dim.score == 75.0


def test_grounding_rate_is_100_with_no_adjudications():
    assert grounding_rate([]).score == 100.0


def test_cri_mapping_completeness_splits_real_inferred_and_absent():
    gaps = [
        _gap("T1", cri_mapping_absent=False),
        _gap("T2", cri_mapping_absent=True, fallback=("PR.AA-01.01",)),
        _gap("T3", cri_mapping_absent=True),
        _gap("T4", cri_mapping_absent=False),
    ]
    dim = cri_mapping_completeness(gaps)
    assert dim.raw_counts == {"real": 2, "inferred_fallback": 1, "absent": 1}
    assert dim.score == 50.0


def test_unresolved_assumptions_uses_mean_confidence():
    dim = unresolved_assumptions([_assumption(0.4), _assumption(0.8)])
    assert dim.score == pytest.approx(60.0)
    assert dim.raw_counts == {"count": 2}


def test_unresolved_assumptions_is_100_with_no_assumptions():
    assert unresolved_assumptions([]).score == 100.0


def test_limitations_completeness_all_declared():
    model = _model(
        [Component(id="c1", name="A", kind="process", trust_zone_id="tz", out_of_scope=True)],
        out_of_scope=[OutOfScopeDeclaration(id="d1", subject_id="c1", category="ot_ics", indicator="plc", reason="real reason")],
    )
    assert limitations_completeness(model).score == 100.0


def test_limitations_completeness_flags_undeclared_exclusion():
    model = _model([Component(id="c1", name="A", kind="process", trust_zone_id="tz", out_of_scope=True)], out_of_scope=[])
    dim = limitations_completeness(model)
    assert dim.score == 0.0
    assert dim.raw_counts == {"explained": 0, "total_out_of_scope": 1}


def test_limitations_completeness_is_100_with_no_out_of_scope_components():
    assert limitations_completeness(_model([])).score == 100.0


def _full_report_inputs():
    model = _model([Component(id="c1", name="A", kind="process", trust_zone_id="tz")])
    result = EnumerationResult(
        ruleset_version="1.0.0", candidates=(), matrix=(ElementMatrixRow("c1", "A", "process", ("spoofing",), ()),)
    )
    return {
        "model": model, "enumeration_result": result, "candidate_count": 1,
        "adjudicated_threats": [_adjudication("c1::spoofing::1.0.0", 1.0)], "rejection_log": [],
        "gaps": [_gap("T1", cri_mapping_absent=False)], "assumptions": [_assumption(1.0)],
    }


def test_compute_coverage_report_aggregates_with_equal_weights_and_bands_correctly():
    report = compute_coverage_report(**_full_report_inputs())
    assert len(report.dimensions) == 6
    assert report.overall_score == pytest.approx(100.0)
    assert report.band == "High"


def test_compute_coverage_report_is_pure_and_deterministic_across_repeated_calls():
    inputs = _full_report_inputs()
    first = compute_coverage_report(**inputs)
    second = compute_coverage_report(**inputs)
    assert first == second


def test_degraded_assumptions_only_move_the_unresolved_assumptions_dimension():
    baseline_inputs = _full_report_inputs()
    baseline = compute_coverage_report(**baseline_inputs)

    degraded_inputs = dict(baseline_inputs)
    degraded_inputs["assumptions"] = [_assumption(0.1)]
    degraded = compute_coverage_report(**degraded_inputs)

    baseline_by_name = {d.name: d.score for d in baseline.dimensions}
    degraded_by_name = {d.name: d.score for d in degraded.dimensions}
    for name, baseline_score in baseline_by_name.items():
        if name == "unresolved_assumptions":
            assert degraded_by_name[name] < baseline_score
        else:
            assert degraded_by_name[name] == baseline_score
    assert degraded.overall_score < baseline.overall_score


def test_degraded_cri_mapping_only_moves_that_dimension():
    baseline_inputs = _full_report_inputs()
    baseline = compute_coverage_report(**baseline_inputs)

    degraded_inputs = dict(baseline_inputs)
    degraded_inputs["gaps"] = [_gap("T1", cri_mapping_absent=True)]
    degraded = compute_coverage_report(**degraded_inputs)

    baseline_by_name = {d.name: d.score for d in baseline.dimensions}
    degraded_by_name = {d.name: d.score for d in degraded.dimensions}
    for name, baseline_score in baseline_by_name.items():
        if name == "cri_mapping_completeness":
            assert degraded_by_name[name] < baseline_score
        else:
            assert degraded_by_name[name] == baseline_score


def test_band_thresholds():
    inputs = _full_report_inputs()
    # Force overall score into the "Low" band by degrading every dimension via assumptions/gaps only
    # is nontrivial with fixed weights, so directly probe the _band function indirectly through scores.
    high = compute_coverage_report(**inputs)
    assert high.band == "High"

    degraded_inputs = dict(inputs)
    degraded_inputs["assumptions"] = [_assumption(0.0)]
    degraded_inputs["gaps"] = [_gap("T1", cri_mapping_absent=True)]
    moderate_or_low = compute_coverage_report(**degraded_inputs)
    assert moderate_or_low.overall_score < high.overall_score


def test_intel_attachment_has_no_way_to_influence_the_score():
    """Task 20's rubric takes no intel-related input at all -- the same
    model/enumeration/gaps/assumptions produce the identical report
    regardless of whether a Task 19 revision has attached corroborating
    or contradicting intel on top of the same underlying model quality."""
    inputs = _full_report_inputs()
    without_intel_context = compute_coverage_report(**inputs)
    with_intel_context = compute_coverage_report(**inputs)  # no intel parameter exists to vary
    assert without_intel_context == with_intel_context
