from app.services.enumeration.adjudication import (
    INVALIDATION_OUT_OF_SCOPE,
    INVALIDATION_REACHABILITY,
    VERDICT_APPLICABLE,
    VERDICT_NOT_APPLICABLE,
    adjudicate,
)
from app.services.enumeration.bridge import BridgedTechnique
from app.services.enumeration.engine import CandidateThreat
from app.services.systemmodel.models import Component, Dataflow, SystemModel, TrustZone


def _model(**kwargs) -> SystemModel:
    defaults = {
        "id": "p1",
        "version": 1,
        "parent_version": None,
        "trust_zones": [TrustZone(id="tz1", name="Internal", trust_rating=1)],
    }
    defaults.update(kwargs)
    return SystemModel(**defaults)


def _bridged(score: float = 0.03) -> list[BridgedTechnique]:
    return [BridgedTechnique(technique_id="T1", technique_name="X", matrix="enterprise", capec_ids=("CAPEC-1",), fused_score=score)]


def test_reachable_grounded_component_is_applicable():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids={"c1"})
    assert result.verdict == VERDICT_APPLICABLE
    assert result.invalidation_condition is None
    assert result.evidence_ref == "T1"
    assert result.citation_score == 0.03


def test_unreachable_component_is_not_applicable_with_reachability_invalidation():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids=set())
    assert result.verdict == VERDICT_NOT_APPLICABLE
    assert result.invalidation_condition is not None
    assert result.invalidation_condition.kind == INVALIDATION_REACHABILITY
    assert result.invalidation_condition.entity_id == "c1"


def test_unreachable_dataflow_checked_via_source_entity_not_flow_id():
    model = _model(
        components=[
            Component(id="c1", name="A", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="B", kind="process", trust_zone_id="tz1"),
        ],
        dataflows=[Dataflow(id="f1", name="x", source_id="c1", destination_id="c2")],
    )
    candidate = CandidateThreat(id="f1::tampering::1.0.0", element_id="f1", element_kind="dataflow", framework="stride", category="tampering", ruleset_version="1.0.0")

    reachable = adjudicate(candidate, model, _bridged(), reachable_entity_ids={"c1"})
    assert reachable.verdict == VERDICT_APPLICABLE

    unreachable = adjudicate(candidate, model, _bridged(), reachable_entity_ids=set())
    assert unreachable.verdict == VERDICT_NOT_APPLICABLE
    assert unreachable.invalidation_condition.entity_id == "c1"


def test_out_of_scope_component_is_not_applicable_with_out_of_scope_invalidation():
    model = _model(
        components=[
            Component(id="scada", name="SCADA", kind="datastore", trust_zone_id="tz1", out_of_scope=True)
        ]
    )
    candidate = CandidateThreat(id="scada::tampering::1.0.0", element_id="scada", element_kind="datastore", framework="stride", category="tampering", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids={"scada"})
    assert result.verdict == VERDICT_NOT_APPLICABLE
    assert result.invalidation_condition.kind == INVALIDATION_OUT_OF_SCOPE
    assert result.invalidation_condition.entity_id == "scada"


def test_out_of_scope_dataflow_endpoint_is_not_applicable():
    model = _model(
        components=[
            Component(id="gateway", name="Gateway", kind="process", trust_zone_id="tz1"),
            Component(id="scada", name="SCADA", kind="datastore", trust_zone_id="tz1", out_of_scope=True),
        ],
        dataflows=[Dataflow(id="f1", name="x", source_id="gateway", destination_id="scada")],
    )
    candidate = CandidateThreat(id="f1::tampering::1.0.0", element_id="f1", element_kind="dataflow", framework="stride", category="tampering", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids={"gateway"})
    assert result.verdict == VERDICT_NOT_APPLICABLE
    assert result.invalidation_condition.kind == INVALIDATION_OUT_OF_SCOPE


def test_out_of_scope_takes_precedence_over_reachability():
    model = _model(
        components=[
            Component(id="scada", name="SCADA", kind="datastore", trust_zone_id="tz1", out_of_scope=True)
        ]
    )
    candidate = CandidateThreat(id="scada::tampering::1.0.0", element_id="scada", element_kind="datastore", framework="stride", category="tampering", ruleset_version="1.0.0")
    # unreachable AND out of scope: out-of-scope reason should win
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids=set())
    assert result.invalidation_condition.kind == INVALIDATION_OUT_OF_SCOPE


def test_linddun_candidate_exempt_from_reachability_check():
    model = _model(components=[Component(id="c1", name="Svc", kind="datastore", trust_zone_id="tz1")])
    candidate = CandidateThreat(id="c1::linkability::1.0.0", element_id="c1", element_kind="datastore", framework="linddun", category="linkability", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids=set())
    assert result.verdict == VERDICT_APPLICABLE


def test_evidence_ref_picks_highest_scoring_technique():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    bridged = [
        BridgedTechnique(technique_id="Low", technique_name="Low", matrix="enterprise", capec_ids=(), fused_score=0.01),
        BridgedTechnique(technique_id="High", technique_name="High", matrix="enterprise", capec_ids=(), fused_score=0.09),
    ]
    result = adjudicate(candidate, model, bridged, reachable_entity_ids={"c1"})
    assert result.evidence_ref == "High"
    assert result.citation_score == 0.09


def test_applicable_records_never_carry_invalidation_condition():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = adjudicate(candidate, model, _bridged(), reachable_entity_ids={"c1"})
    assert result.verdict == VERDICT_APPLICABLE
    assert result.invalidation_condition is None
