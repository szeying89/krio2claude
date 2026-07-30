from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.path_enumeration import AttackPath, PathEnumerationResult, PathStep
from app.services.kb.models import TechniqueChunk
from app.services.mitigation.gap_analysis import compute_technique_gaps, techniques_in_paths
from app.services.mitigation.inventory import ControlInventoryEntry


def _technique(id_="T1190", d3fend_ids=("D3-MFA", "D3-ACCT")):
    return TechniqueChunk(
        id=id_,
        matrix="enterprise",
        name="Exploit Public-Facing Application",
        tactics=("initial-access",),
        description="Adversary exploits a weakness in an internet-facing host or application.",
        detection="",
        platforms=(),
        data_sources=(),
        relationships={"d3fend_inferred": d3fend_ids},
    )


def _statement(profile_id="PR.PS-02.01", mapped=("T1190",), tiers=(1, 2, 3, 4)):
    return DiagnosticStatement(
        outline_id="1",
        profile_id=profile_id,
        csf_path=("PROTECT",),
        name="Application hardening",
        text="Public-facing applications are hardened against exploitation.",
        applicable_tiers=tiers,
        mapped_technique_ids=mapped,
    )


def _path(technique_ids):
    steps = tuple(
        PathStep(
            source_entity_id="a",
            target_entity_id="b",
            category="tampering",
            technique_id=tid,
            technique_name=tid,
            matrix="enterprise",
            tactic="initial-access",
            dataflow_id="f1",
            candidate_threat_id=f"cand-{tid}",
            likelihood=0.5,
        )
        for tid in technique_ids
    )
    return AttackPath(id="path-1", entry_point="a", target="b", steps=steps, tactic_sequence=("initial-access",), aggregate_likelihood=0.5)


def test_techniques_in_paths_collects_unique_technique_ids_across_all_steps():
    result = PathEnumerationResult(paths=(_path(["T1190", "T1210"]), _path(["T1190"])), capped=False)
    assert techniques_in_paths(result) == {"T1190", "T1210"}


def test_partial_coverage_reports_gap_only_for_uncovered_ids():
    technique = _technique(d3fend_ids=("D3-MFA", "D3-ACCT"))
    inventory = [ControlInventoryEntry(control_id="c1", control_name="MFA", d3fend_ids=("D3-MFA",), cri_statement_ids=())]
    results = compute_technique_gaps({"T1190"}, {"T1190": technique}, inventory, [], tier=None)
    assert len(results) == 1
    gap = results[0]
    assert gap.d3fend_required_ids == ("D3-ACCT", "D3-MFA")
    assert gap.d3fend_observed_ids == ("D3-MFA",)
    assert gap.d3fend_gap_ids == ("D3-ACCT",)


def test_removing_the_control_raises_the_expected_d3fend_and_cri_gaps():
    technique = _technique(d3fend_ids=("D3-MFA",))
    statement = _statement()

    covered_inventory = [ControlInventoryEntry(control_id="c1", control_name="App hardening", d3fend_ids=("D3-MFA",), cri_statement_ids=(statement.profile_id,))]
    covered = compute_technique_gaps({"T1190"}, {"T1190": technique}, covered_inventory, [statement], tier=None)[0]
    assert covered.d3fend_gap_ids == ()
    assert covered.cri_gap_statement_ids == ()

    without_control = compute_technique_gaps({"T1190"}, {"T1190": technique}, [], [statement], tier=None)[0]
    assert without_control.d3fend_gap_ids == ("D3-MFA",)
    assert without_control.cri_gap_statement_ids == (statement.profile_id,)


def test_tier_filtering_excludes_out_of_tier_statements_from_gap_and_in_tier_lists():
    technique = _technique()
    tier1_only = _statement(profile_id="PR.PS-02.01", tiers=(1,))
    all_tiers = _statement(profile_id="DE.CM-01.03", tiers=(1, 2, 3, 4))

    results = compute_technique_gaps({"T1190"}, {"T1190": technique}, [], [tier1_only, all_tiers], tier=3)[0]
    assert results.cri_in_tier_statement_ids == ("DE.CM-01.03",)
    assert results.cri_gap_statement_ids == ("DE.CM-01.03",)
    assert "PR.PS-02.01" not in results.cri_in_tier_statement_ids
    assert "PR.PS-02.01" not in results.cri_gap_statement_ids


def test_tier_none_treats_every_mapped_statement_as_in_scope():
    technique = _technique()
    tier1_only = _statement(profile_id="PR.PS-02.01", tiers=(1,))
    results = compute_technique_gaps({"T1190"}, {"T1190": technique}, [], [tier1_only], tier=None)[0]
    assert results.cri_in_tier_statement_ids == ("PR.PS-02.01",)
    assert results.cri_gap_statement_ids == ("PR.PS-02.01",)


def test_technique_with_no_cri_mapping_is_tagged_mapping_absent_and_never_merged_with_real_mappings():
    technique = _technique(id_="T9999")
    unrelated_statement = _statement(profile_id="PR.PS-02.01", mapped=("T1190",))
    results = compute_technique_gaps({"T9999"}, {"T9999": technique}, [], [unrelated_statement], tier=None)[0]
    assert results.cri_mapping_absent is True
    assert results.cri_in_tier_statement_ids == ()
    assert results.cri_gap_statement_ids == ()


def test_mapping_absent_fallback_uses_lexical_match_against_technique_name_and_description_only():
    technique = TechniqueChunk(
        id="T9999",
        matrix="enterprise",
        name="Application Hardening Weakness",
        tactics=("initial-access",),
        description="Exploitation of application hardening weaknesses in public-facing hosts.",
        detection="",
        platforms=(),
        data_sources=(),
        relationships={},
    )
    fallback_candidate = DiagnosticStatement(
        outline_id="1",
        profile_id="PR.PS-02.01",
        csf_path=("PROTECT",),
        name="Application hardening",
        text="Public-facing applications are hardened against exploitation weaknesses.",
        applicable_tiers=(1, 2, 3, 4),
        mapped_technique_ids=(),  # no authoritative/heuristic bridge mapping at all
    )
    results = compute_technique_gaps({"T9999"}, {"T9999": technique}, [], [fallback_candidate], tier=None)[0]
    assert results.cri_mapping_absent is True
    assert results.cri_mapping_inferred_fallback_ids == ("PR.PS-02.01",)
    # never merged into the real gap-statement / in-tier lists
    assert results.cri_in_tier_statement_ids == ()
    assert results.cri_gap_statement_ids == ()


def test_technique_not_present_in_kb_dict_still_produces_a_result_with_empty_d3fend_requirements():
    results = compute_technique_gaps({"T0000"}, {}, [], [], tier=None)
    assert len(results) == 1
    assert results[0].d3fend_required_ids == ()
    assert results[0].cri_mapping_absent is True
    assert results[0].cri_mapping_inferred_fallback_ids == ()


def test_multiple_techniques_each_get_their_own_independent_gap_result_sorted_by_id():
    t1 = _technique(id_="T1190", d3fend_ids=("D3-MFA",))
    t2 = _technique(id_="T1210", d3fend_ids=("D3-ACCT",))
    results = compute_technique_gaps({"T1210", "T1190"}, {"T1190": t1, "T1210": t2}, [], [], tier=None)
    assert [r.technique_id for r in results] == ["T1190", "T1210"]
