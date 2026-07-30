from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement, RegulatoryReference
from app.services.enumeration.path_enumeration import AttackPath, PathStep
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.risk.scoring import impact_weight, score_path, statement_density


def _gap(
    technique_id="T1190",
    d3fend_gap_ids=(),
    cri_mapping_absent=False,
    cri_in_tier_statement_ids=(),
    cri_gap_statement_ids=(),
):
    return TechniqueGapAnalysis(
        technique_id=technique_id,
        d3fend_required_ids=(),
        d3fend_observed_ids=(),
        d3fend_gap_ids=d3fend_gap_ids,
        cri_mapping_absent=cri_mapping_absent,
        cri_in_tier_statement_ids=cri_in_tier_statement_ids,
        cri_gap_statement_ids=cri_gap_statement_ids,
        cri_mapping_inferred_fallback_ids=(),
    )


def _path(technique_id="T1190", likelihood=0.5):
    step = PathStep(
        source_entity_id="a",
        target_entity_id="b",
        category="tampering",
        technique_id=technique_id,
        technique_name=technique_id,
        matrix="enterprise",
        tactic="initial-access",
        dataflow_id="f1",
        candidate_threat_id="cand-1",
        likelihood=likelihood,
    )
    return AttackPath(
        id="path-1",
        entry_point="a",
        target="b",
        steps=(step,),
        tactic_sequence=("initial-access",),
        aggregate_likelihood=likelihood,
    )


def _statement(profile_id="PR.PS-02.01", refs=()):
    return DiagnosticStatement(
        outline_id="1",
        profile_id=profile_id,
        csf_path=("PROTECT",),
        name="Application hardening",
        text="Public-facing applications are hardened.",
        applicable_tiers=(1, 2, 3, 4),
        regulatory_references=refs,
    )


def test_impact_weight_increases_with_business_criticality():
    low = impact_weight(BusinessCriticality.LOW, tier=None)
    high = impact_weight(BusinessCriticality.CRITICAL, tier=None)
    assert low < high


def test_impact_weight_tier_multiplier_only_applies_when_tier_known():
    untiered = impact_weight(BusinessCriticality.HIGH, tier=None)
    tier1 = impact_weight(BusinessCriticality.HIGH, tier=1)
    tier4 = impact_weight(BusinessCriticality.HIGH, tier=4)
    assert tier1 == untiered  # tier 1 multiplier is 1.0, so it matches the untiered baseline
    assert tier4 < tier1


def test_statement_density_is_zero_when_no_cri_mapping_or_no_in_tier_statements():
    assert statement_density(_gap(cri_mapping_absent=True)) == 0.0
    assert statement_density(_gap(cri_in_tier_statement_ids=())) == 0.0


def test_statement_density_is_fraction_of_in_tier_statements_unsatisfied():
    gap = _gap(
        cri_in_tier_statement_ids=("A", "B", "C", "D"),
        cri_gap_statement_ids=("A", "B"),
    )
    assert statement_density(gap) == 0.5


def test_score_is_monotonically_increasing_in_likelihood():
    gap = _gap()
    low = score_path(_path(likelihood=0.2), {"T1190": gap}, BusinessCriticality.HIGH, None, {}, {})
    high = score_path(_path(likelihood=0.8), {"T1190": gap}, BusinessCriticality.HIGH, None, {}, {})
    assert high.score > low.score


def test_score_is_monotonically_increasing_in_business_criticality():
    gap = _gap()
    low = score_path(_path(), {"T1190": gap}, BusinessCriticality.LOW, None, {}, {})
    high = score_path(_path(), {"T1190": gap}, BusinessCriticality.CRITICAL, None, {}, {})
    assert high.score > low.score


def test_score_is_monotonically_increasing_in_statement_density():
    sparse = _gap(cri_in_tier_statement_ids=("A", "B"), cri_gap_statement_ids=())
    dense = _gap(cri_in_tier_statement_ids=("A", "B"), cri_gap_statement_ids=("A", "B"))
    low = score_path(_path(), {"T1190": sparse}, BusinessCriticality.HIGH, None, {}, {})
    high = score_path(_path(), {"T1190": dense}, BusinessCriticality.HIGH, None, {}, {})
    assert high.score > low.score


def test_changing_tier_changes_score_only_through_impact_weight():
    gap = _gap(cri_in_tier_statement_ids=("A", "B"), cri_gap_statement_ids=("A",))
    tier1 = score_path(_path(), {"T1190": gap}, BusinessCriticality.HIGH, 1, {}, {})
    tier4 = score_path(_path(), {"T1190": gap}, BusinessCriticality.HIGH, 4, {}, {})

    assert tier1.factors.likelihood == tier4.factors.likelihood
    assert tier1.factors.statement_density == tier4.factors.statement_density
    assert tier1.factors.impact_weight != tier4.factors.impact_weight
    expected_ratio = tier1.factors.impact_weight / tier4.factors.impact_weight
    assert tier1.score / tier4.score == expected_ratio


def test_regulatory_references_resolve_to_catalogue_entries():
    statement = _statement(
        profile_id="PR.PS-02.01", refs=(RegulatoryReference(short_code="DORA-9", count=1),)
    )
    gap = _gap(cri_in_tier_statement_ids=("PR.PS-02.01",), cri_gap_statement_ids=("PR.PS-02.01",))
    catalog = {"DORA-9": {"document_name": "DORA Article 9", "issuing_organization": "EU"}}

    finding = score_path(
        _path(),
        {"T1190": gap},
        BusinessCriticality.HIGH,
        None,
        {"PR.PS-02.01": statement},
        catalog,
    )
    assert len(finding.regulatory_exposure) == 1
    exposure = finding.regulatory_exposure[0]
    assert exposure.short_code == "DORA-9"
    assert exposure.document_name == "DORA Article 9"


def test_unresolved_regulatory_reference_is_silently_skipped_not_fabricated():
    statement = _statement(
        profile_id="PR.PS-02.01", refs=(RegulatoryReference(short_code="UNKNOWN-REG", count=1),)
    )
    gap = _gap(cri_in_tier_statement_ids=("PR.PS-02.01",), cri_gap_statement_ids=("PR.PS-02.01",))

    finding = score_path(
        _path(),
        {"T1190": gap},
        BusinessCriticality.HIGH,
        None,
        {"PR.PS-02.01": statement},
        {},  # empty catalog: the short code cannot be resolved
    )
    assert finding.regulatory_exposure == ()


def test_csf_functions_derived_from_in_tier_statement_ids():
    gap = _gap(cri_in_tier_statement_ids=("GV.OC-01.01", "PR.AA-05.01"))
    finding = score_path(_path(), {"T1190": gap}, BusinessCriticality.HIGH, None, {}, {})
    assert finding.csf_functions == ("GV", "PR")


def test_technique_not_in_gaps_by_technique_is_simply_excluded_from_relevant_gaps():
    finding = score_path(_path(technique_id="T9999"), {}, BusinessCriticality.HIGH, None, {}, {})
    assert finding.factors.statement_density == 0.0
    assert finding.factors.cri_mapping_absent is True
    assert finding.csf_functions == ()
