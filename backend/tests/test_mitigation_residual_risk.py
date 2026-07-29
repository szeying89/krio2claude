from app.models.enums import BusinessCriticality
from app.services.enumeration.path_enumeration import AttackPath, PathEnumerationResult, PathStep
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation
from app.services.mitigation.residual_risk import apply_mitigations, compute_residual_risk


def _gap(technique_id="T1190", d3fend_gap_ids=("D3-MFA",), cri_gap_statement_ids=("PR.AA-05.01",)):
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


def _rec(technique_id="T1190", d3fend_id="D3-MFA", cri_statement_ids=("PR.AA-05.01",)):
    return MitigationRecommendation(
        id=f"rec-{technique_id}-{d3fend_id}",
        technique_id=technique_id,
        d3fend_id=d3fend_id,
        cri_statement_ids=cri_statement_ids,
        guidance="Do the thing.",
        referenced_entity_ids=(),
        effort=2,
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


def test_apply_mitigations_removes_only_the_recommended_ids():
    gaps = [_gap(d3fend_gap_ids=("D3-MFA", "D3-ACCT"), cri_gap_statement_ids=("PR.AA-05.01", "PR.AA-05.02"))]
    recs = [_rec(d3fend_id="D3-MFA", cri_statement_ids=("PR.AA-05.01",))]

    mitigated = apply_mitigations(gaps, recs)
    assert mitigated[0].d3fend_gap_ids == ("D3-ACCT",)
    assert mitigated[0].cri_gap_statement_ids == ("PR.AA-05.02",)


def test_apply_mitigations_never_mutates_input_gaps():
    gaps = [_gap()]
    original = gaps[0]
    apply_mitigations(gaps, [_rec()])
    assert gaps[0] is original
    assert gaps[0].d3fend_gap_ids == ("D3-MFA",)


def test_apply_mitigations_leaves_unrelated_techniques_untouched():
    gaps = [_gap(technique_id="T1190"), _gap(technique_id="T9999", d3fend_gap_ids=("D3-OTHER",))]
    mitigated = apply_mitigations(gaps, [_rec(technique_id="T1190")])
    other = next(g for g in mitigated if g.technique_id == "T9999")
    assert other.d3fend_gap_ids == ("D3-OTHER",)


def test_residual_risk_strictly_decreases_when_mitigation_covers_a_path_critical_technique():
    gaps = [_gap()]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1190"),), capped=False)
    recs = [_rec()]

    comparison = compute_residual_risk(
        path_result, gaps, recs, BusinessCriticality.HIGH, tier=None, cri_statements=[], regulatory_documents={}
    )
    assert comparison.residual_total_score < comparison.baseline_total_score
    assert comparison.risk_reduction > 0


def test_residual_risk_unchanged_when_mitigation_does_not_cover_any_path_technique():
    gaps = [_gap(technique_id="T1190"), _gap(technique_id="T9999", d3fend_gap_ids=("D3-OTHER",))]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1190"),), capped=False)
    recs = [_rec(technique_id="T9999", d3fend_id="D3-OTHER", cri_statement_ids=())]

    comparison = compute_residual_risk(
        path_result, gaps, recs, BusinessCriticality.HIGH, tier=None, cri_statements=[], regulatory_documents={}
    )
    assert comparison.risk_reduction == 0.0
    assert comparison.baseline_total_score == comparison.residual_total_score
