from app.models.enums import BusinessCriticality
from app.services.enumeration.path_enumeration import AttackPath, PathEnumerationResult, PathStep
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.roadmap import build_roadmap

# The risk score (app/services/risk/scoring.py) only moves via CRI
# unsatisfied-statement density -- D3FEND gap count is informational only
# (Task 16 intentionally scores on "unsatisfied-statement density," which
# means CRI statements, not D3FEND countermeasures). So every fixture here
# gives each technique a real CRI gap to close, or a mitigation would show
# zero risk reduction regardless of ordering.


def _gap(technique_id, d3fend_gap_ids=(), cri_gap_statement_ids=()):
    return TechniqueGapAnalysis(
        technique_id=technique_id,
        d3fend_required_ids=d3fend_gap_ids,
        d3fend_observed_ids=(),
        d3fend_gap_ids=d3fend_gap_ids,
        cri_mapping_absent=False,
        cri_in_tier_statement_ids=cri_gap_statement_ids,
        cri_gap_statement_ids=cri_gap_statement_ids,
        cri_mapping_inferred_fallback_ids=(),
    )


def _rec(rec_id, technique_id, d3fend_id, cri_statement_ids=(), effort=2):
    return MitigationRecommendation(
        id=rec_id,
        technique_id=technique_id,
        d3fend_id=d3fend_id,
        cri_statement_ids=cri_statement_ids,
        guidance="Do the thing.",
        referenced_entity_ids=(),
        effort=effort,
    )


def _path(path_id, technique_id, likelihood=0.5):
    step = PathStep(
        source_entity_id="a",
        target_entity_id="b",
        category="tampering",
        technique_id=technique_id,
        technique_name=technique_id,
        matrix="enterprise",
        tactic="initial-access",
        dataflow_id="f1",
        candidate_threat_id=f"cand-{technique_id}",
        likelihood=likelihood,
    )
    return AttackPath(
        id=path_id,
        entry_point="a",
        target="b",
        steps=(step,),
        tactic_sequence=("initial-access",),
        aggregate_likelihood=likelihood,
    )


def test_empty_recommendations_produces_empty_roadmap():
    assert build_roadmap(
        PathEnumerationResult(paths=(), capped=False), [], [], BusinessCriticality.HIGH, None, [], {}
    ) == ()


def test_roadmap_orders_by_risk_reduction_per_unit_effort():
    # T1's path has far higher likelihood than T2's, so closing T1's CRI
    # gap yields far more risk reduction at equal effort. Recommendation
    # ids are deliberately the *reverse* of the expected order, so this
    # only passes if the ranking is genuinely ratio-driven rather than an
    # accidental alphabetical tie-break.
    gaps = [
        _gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-01.01",)),
        _gap("T2", d3fend_gap_ids=("D3-B",), cri_gap_statement_ids=("PR.AA-02.01",)),
    ]
    rec_t1 = _rec("z-rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-01.01",), effort=2)
    rec_t2 = _rec("a-rec-t2", "T2", "D3-B", cri_statement_ids=("PR.AA-02.01",), effort=2)
    path_result = PathEnumerationResult(
        paths=(_path("path-1", "T1", likelihood=0.9), _path("path-2", "T2", likelihood=0.05)),
        capped=False,
    )

    phases = build_roadmap(
        path_result, gaps, [rec_t2, rec_t1], BusinessCriticality.HIGH, None, [], {}, phase_size=1
    )
    assert len(phases) == 2
    assert phases[0].recommendations == (rec_t1,)
    assert phases[1].recommendations == (rec_t2,)


def test_roadmap_ordering_is_deterministic_across_repeated_calls():
    gaps = [
        _gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-01.01",)),
        _gap("T2", d3fend_gap_ids=("D3-B",), cri_gap_statement_ids=("PR.AA-02.01",)),
    ]
    recs = [
        _rec("rec-t2", "T2", "D3-B", cri_statement_ids=("PR.AA-02.01",)),
        _rec("rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-01.01",)),
    ]
    path_result = PathEnumerationResult(
        paths=(_path("path-1", "T1", 0.5), _path("path-2", "T2", 0.5)), capped=False
    )

    first = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {})
    second = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {})
    assert [p.recommendations for p in first] == [p.recommendations for p in second]


def test_cumulative_risk_reduction_increases_across_phases():
    gaps = [
        _gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-01.01",)),
        _gap("T2", d3fend_gap_ids=("D3-B",), cri_gap_statement_ids=("PR.AA-02.01",)),
    ]
    recs = [
        _rec("rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-01.01",)),
        _rec("rec-t2", "T2", "D3-B", cri_statement_ids=("PR.AA-02.01",)),
    ]
    path_result = PathEnumerationResult(
        paths=(_path("path-1", "T1", 0.6), _path("path-2", "T2", 0.4)), capped=False
    )

    phases = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {}, phase_size=1)
    assert phases[0].cumulative_risk_reduction > 0
    assert phases[1].cumulative_risk_reduction > phases[0].cumulative_risk_reduction
    assert phases[0].cumulative_risk_reduction == phases[0].phase_risk_reduction


def test_phase_reports_diagnostic_statements_it_newly_closes():
    gaps = [_gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-05.01", "PR.AA-05.02"))]
    recs = [_rec("rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-05.01", "PR.AA-05.02"))]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1"),), capped=False)

    phases = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {})
    assert phases[0].diagnostic_statements_closed == ("PR.AA-05.01", "PR.AA-05.02")


def test_phase_reports_attack_paths_it_fully_closes():
    gaps = [_gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-05.01",))]
    recs = [_rec("rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-05.01",))]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1"),), capped=False)

    phases = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {})
    assert phases[0].attack_paths_closed == ("path-1",)


def test_path_not_closed_when_one_of_its_techniques_still_has_a_gap():
    # path-1 uses both T1 and T2; only T1's gap is mitigated, so the path
    # as a whole must not be reported as closed.
    step1 = PathStep(
        source_entity_id="a", target_entity_id="b", category="tampering", technique_id="T1",
        technique_name="T1", matrix="enterprise", tactic="initial-access", dataflow_id="f1",
        candidate_threat_id="cand-1", likelihood=0.5,
    )
    step2 = PathStep(
        source_entity_id="b", target_entity_id="c", category="tampering", technique_id="T2",
        technique_name="T2", matrix="enterprise", tactic="initial-access", dataflow_id="f2",
        candidate_threat_id="cand-2", likelihood=0.5,
    )
    path = AttackPath(
        id="path-1", entry_point="a", target="c", steps=(step1, step2),
        tactic_sequence=("initial-access", "initial-access"), aggregate_likelihood=0.25,
    )
    gaps = [
        _gap("T1", d3fend_gap_ids=("D3-A",), cri_gap_statement_ids=("PR.AA-05.01",)),
        _gap("T2", d3fend_gap_ids=("D3-B",), cri_gap_statement_ids=("PR.AA-05.02",)),
    ]
    recs = [_rec("rec-t1", "T1", "D3-A", cri_statement_ids=("PR.AA-05.01",))]  # only T1 is mitigated
    path_result = PathEnumerationResult(paths=(path,), capped=False)

    phases = build_roadmap(path_result, gaps, recs, BusinessCriticality.HIGH, None, [], {})
    assert phases[0].attack_paths_closed == ()
