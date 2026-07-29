from app.services.assurance.critique_detectors import (
    CATEGORY_MISSED_THREAT,
    CATEGORY_OVER_TRUSTED_BOUNDARY,
    CATEGORY_QUESTIONABLE_ASSUMPTION,
    CATEGORY_UNDER_SCOPED_TIERING,
    CATEGORY_WEAK_MITIGATION,
    detect_missed_threats,
    detect_over_trusted_boundaries,
    detect_questionable_assumptions,
    detect_under_scoped_tiering,
    detect_weak_mitigations,
)
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.adjudication import Adjudication
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.modelbuilding.models import Assumption
from app.services.systemmodel.models import (
    Component,
    Dataflow,
    DeclaredControl,
    SystemModel,
    TrustZone,
)


def _model(dataflows=(), components=None, declared_controls=()):
    if components is None:
        components = [
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gw", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="Database", kind="datastore", trust_zone_id="internal"),
        ]
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="dmz", name="DMZ", trust_rating=1), TrustZone(id="internal", name="Internal", trust_rating=3)],
        components=components,
        dataflows=list(dataflows),
        declared_controls=list(declared_controls),
    )


def _adjudication(candidate_id, verdict="applicable", citation_score=1.0):
    return Adjudication(
        candidate_threat_id=candidate_id, verdict=verdict, rationale="r", evidence_ref="T1",
        citation_score=citation_score, invalidation_condition=None,
    )


def test_missed_threat_flags_a_boundary_crossing_dataflow_with_zero_adjudications():
    flow = Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")
    model = _model(dataflows=[flow])
    issues = detect_missed_threats(model, adjudicated_threats=[])
    assert len(issues) == 1
    assert issues[0].category == CATEGORY_MISSED_THREAT
    assert "bk-02" in issues[0].cited_element_ids


def test_missed_threat_does_not_fire_when_the_flow_has_any_adjudication():
    flow = Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")
    model = _model(dataflows=[flow])
    issues = detect_missed_threats(model, adjudicated_threats=[_adjudication("bk-02::tampering::1.0.0")])
    assert issues == []


def test_missed_threat_does_not_fire_for_same_zone_flows():
    flow = Dataflow(id="f1", name="login", source_id="client", destination_id="gw")
    model = _model(dataflows=[flow])
    assert detect_missed_threats(model, adjudicated_threats=[]) == []


def test_over_trusted_boundary_flags_all_not_applicable_into_higher_trust_zone():
    flow = Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")
    model = _model(dataflows=[flow])
    issues = detect_over_trusted_boundaries(
        model, adjudicated_threats=[_adjudication("bk-02::tampering::1.0.0", verdict="not_applicable")]
    )
    assert len(issues) == 1
    assert issues[0].category == CATEGORY_OVER_TRUSTED_BOUNDARY
    assert "bk-02" in issues[0].cited_element_ids


def test_over_trusted_boundary_does_not_fire_when_any_verdict_is_applicable():
    flow = Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")
    model = _model(dataflows=[flow])
    issues = detect_over_trusted_boundaries(
        model,
        adjudicated_threats=[
            _adjudication("bk-02::tampering::1.0.0", verdict="not_applicable"),
            _adjudication("bk-02::spoofing::1.0.0", verdict="applicable"),
        ],
    )
    assert issues == []


def test_over_trusted_boundary_does_not_fire_into_a_lower_or_equal_trust_zone():
    flow = Dataflow(id="f1", name="login", source_id="db", destination_id="gw")  # internal -> dmz, downward
    model = _model(dataflows=[flow])
    issues = detect_over_trusted_boundaries(
        model, adjudicated_threats=[_adjudication("f1::tampering::1.0.0", verdict="not_applicable")]
    )
    assert issues == []


def test_weak_mitigation_flags_a_control_that_does_not_close_its_own_entity_gap():
    control = DeclaredControl(id="ctrl-1", name="Encryption at rest", applies_to_ids=("db",))
    model = _model(declared_controls=[control])
    gap = TechniqueGapAnalysis(
        technique_id="T1", d3fend_required_ids=("D3-X",), d3fend_observed_ids=(), d3fend_gap_ids=("D3-X",),
        cri_mapping_absent=False, cri_in_tier_statement_ids=(), cri_gap_statement_ids=(), cri_mapping_inferred_fallback_ids=(),
    )
    issues = detect_weak_mitigations(model, gaps=[gap], entities_by_technique={"T1": ("db",)})
    assert len(issues) == 1
    assert issues[0].category == CATEGORY_WEAK_MITIGATION
    assert issues[0].cited_element_ids == ("db",)


def test_weak_mitigation_does_not_fire_when_control_covers_an_unrelated_entity():
    control = DeclaredControl(id="ctrl-1", name="Encryption at rest", applies_to_ids=("gw",))
    model = _model(declared_controls=[control])
    gap = TechniqueGapAnalysis(
        technique_id="T1", d3fend_required_ids=("D3-X",), d3fend_observed_ids=(), d3fend_gap_ids=("D3-X",),
        cri_mapping_absent=False, cri_in_tier_statement_ids=(), cri_gap_statement_ids=(), cri_mapping_inferred_fallback_ids=(),
    )
    issues = detect_weak_mitigations(model, gaps=[gap], entities_by_technique={"T1": ("db",)})
    assert issues == []


def test_weak_mitigation_does_not_fire_when_gap_is_fully_closed():
    control = DeclaredControl(id="ctrl-1", name="Encryption at rest", applies_to_ids=("db",))
    model = _model(declared_controls=[control])
    gap = TechniqueGapAnalysis(
        technique_id="T1", d3fend_required_ids=(), d3fend_observed_ids=(), d3fend_gap_ids=(),
        cri_mapping_absent=False, cri_in_tier_statement_ids=(), cri_gap_statement_ids=(), cri_mapping_inferred_fallback_ids=(),
    )
    issues = detect_weak_mitigations(model, gaps=[gap], entities_by_technique={"T1": ("db",)})
    assert issues == []


def test_questionable_assumption_flags_low_confidence_only():
    assumptions = [
        Assumption(kind="default", subject_id="c1", message="low", source="agent_generated", confidence=0.2, impact_if_wrong="x"),
        Assumption(kind="default", subject_id="c2", message="high", source="agent_generated", confidence=0.9, impact_if_wrong="x"),
    ]
    issues = detect_questionable_assumptions(assumptions)
    assert len(issues) == 1
    assert issues[0].category == CATEGORY_QUESTIONABLE_ASSUMPTION
    assert issues[0].cited_element_ids == ("c1",)


def _statement(profile_id, tiers):
    return DiagnosticStatement(
        outline_id="1", profile_id=profile_id, csf_path=("PROTECT",), name="n", text="t", applicable_tiers=tiers,
    )


def test_under_scoped_tiering_flags_a_stricter_tier_statement_out_of_scope():
    statement = _statement("PR.AA-01.01", tiers=(1, 2))
    issues = detect_under_scoped_tiering(tier=3, cri_statements=[statement])
    assert len(issues) == 1
    assert issues[0].category == CATEGORY_UNDER_SCOPED_TIERING
    assert issues[0].cited_statement_ids == ("PR.AA-01.01",)


def test_under_scoped_tiering_does_not_fire_when_statement_is_in_scope():
    statement = _statement("PR.AA-01.01", tiers=(1, 2, 3, 4))
    assert detect_under_scoped_tiering(tier=3, cri_statements=[statement]) == []


def test_under_scoped_tiering_never_fires_with_no_tier_computed():
    statement = _statement("PR.AA-01.01", tiers=(1,))
    assert detect_under_scoped_tiering(tier=None, cri_statements=[statement]) == []


def test_under_scoped_tiering_never_fires_at_the_strictest_tier():
    statement = _statement("PR.AA-01.01", tiers=(1,))
    assert detect_under_scoped_tiering(tier=1, cri_statements=[statement]) == []
