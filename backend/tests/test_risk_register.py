from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import AttackPath, PathEnumerationResult, PathStep
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.risk.register import build_csf_rollup, build_risk_register


def _gap(
    technique_id,
    cri_mapping_absent=False,
    cri_in_tier_statement_ids=(),
    cri_gap_statement_ids=(),
    d3fend_gap_ids=(),
):
    return TechniqueGapAnalysis(
        technique_id=technique_id,
        d3fend_required_ids=d3fend_gap_ids,
        d3fend_observed_ids=(),
        d3fend_gap_ids=d3fend_gap_ids,
        cri_mapping_absent=cri_mapping_absent,
        cri_in_tier_statement_ids=cri_in_tier_statement_ids,
        cri_gap_statement_ids=cri_gap_statement_ids,
        cri_mapping_inferred_fallback_ids=(),
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


def test_csf_rollup_groups_by_function_and_computes_density():
    gaps = [
        _gap("T1", cri_in_tier_statement_ids=("GV.OC-01.01", "GV.OC-01.02"), cri_gap_statement_ids=("GV.OC-01.01",)),
        _gap("T2", cri_in_tier_statement_ids=("PR.AA-05.01",), cri_gap_statement_ids=("PR.AA-05.01",)),
    ]
    rollup = build_csf_rollup(gaps)
    by_function = {r.function: r for r in rollup}

    assert by_function["GV"].in_tier_statement_count == 2
    assert by_function["GV"].unsatisfied_statement_count == 1
    assert by_function["GV"].unsatisfied_density == 0.5
    assert by_function["GV"].technique_count == 1

    assert by_function["PR"].in_tier_statement_count == 1
    assert by_function["PR"].unsatisfied_statement_count == 1
    assert by_function["PR"].unsatisfied_density == 1.0


def test_csf_rollup_sums_consistently_with_underlying_gaps():
    gaps = [
        _gap("T1", cri_in_tier_statement_ids=("DE.CM-01.01", "DE.CM-01.02", "DE.CM-01.03"), cri_gap_statement_ids=("DE.CM-01.01",)),
        _gap("T2", cri_in_tier_statement_ids=("DE.CM-01.03", "DE.CM-01.04"), cri_gap_statement_ids=("DE.CM-01.04",)),
    ]
    rollup = build_csf_rollup(gaps)
    de = next(r for r in rollup if r.function == "DE")

    all_in_tier_ids = {sid for g in gaps for sid in g.cri_in_tier_statement_ids}
    all_gap_ids = {sid for g in gaps for sid in g.cri_gap_statement_ids}
    assert de.in_tier_statement_count == len(all_in_tier_ids)
    assert de.unsatisfied_statement_count == len(all_gap_ids)


def test_csf_rollup_excludes_functions_with_no_in_tier_statements():
    gaps = [_gap("T1", cri_mapping_absent=True)]
    assert build_csf_rollup(gaps) == ()


def test_csf_rollup_sorted_with_highest_unsatisfied_density_first():
    gaps = [
        _gap("T1", cri_in_tier_statement_ids=("GV.OC-01.01",), cri_gap_statement_ids=()),
        _gap("T2", cri_in_tier_statement_ids=("DE.CM-01.01",), cri_gap_statement_ids=("DE.CM-01.01",)),
    ]
    rollup = build_csf_rollup(gaps)
    assert rollup[0].function == "DE"
    assert rollup[0].unsatisfied_density == 1.0
    assert rollup[-1].function == "GV"
    assert rollup[-1].unsatisfied_density == 0.0


def test_build_risk_register_produces_one_finding_per_path():
    gaps = [_gap("T1", cri_in_tier_statement_ids=("GV.OC-01.01",), cri_gap_statement_ids=())]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1"), _path("path-2", "T1")), capped=False)

    register = build_risk_register(
        path_result, gaps, BusinessCriticality.HIGH, tier=2, cri_statements=[], regulatory_documents={}
    )
    assert len(register.findings) == 2
    assert register.tier == 2


def test_degraded_mode_when_no_cri_statements_uploaded():
    gaps = [_gap("T1", cri_mapping_absent=True, d3fend_gap_ids=("D3-MFA",))]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1"),), capped=False)

    register = build_risk_register(
        path_result, gaps, BusinessCriticality.HIGH, tier=None, cri_statements=[], regulatory_documents={}
    )
    assert register.degraded is True
    assert register.csf_rollup == ()
    finding = register.findings[0]
    assert finding.csf_functions == ()
    assert finding.regulatory_exposure == ()
    assert finding.factors.cri_gap_count == 0
    assert finding.factors.statement_density == 0.0
    # D3FEND coverage doesn't depend on CRI, so it still surfaces in degraded mode
    assert finding.factors.d3fend_gap_count == 1


def test_not_degraded_when_cri_statements_present_even_if_tier_not_yet_computed():
    statement = DiagnosticStatement(
        outline_id="1",
        profile_id="GV.OC-01.01",
        csf_path=("GOVERN",),
        name="Governance",
        text="Some statement.",
        applicable_tiers=(1, 2, 3, 4),
    )
    gaps = [_gap("T1", cri_in_tier_statement_ids=("GV.OC-01.01",), cri_gap_statement_ids=("GV.OC-01.01",))]
    path_result = PathEnumerationResult(paths=(_path("path-1", "T1"),), capped=False)

    register = build_risk_register(
        path_result,
        gaps,
        BusinessCriticality.HIGH,
        tier=None,
        cri_statements=[statement],
        regulatory_documents={},
    )
    assert register.degraded is False
    assert register.csf_rollup != ()
