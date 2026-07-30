from app.services.enumeration.bridge import BridgedTechnique
from app.services.enumeration.engine import CandidateThreat
from app.services.enumeration.grounding import (
    REASON_NO_CITATION,
    REASON_NO_ENTITY_BINDING,
    REASON_NO_FLOW_BINDING,
    check_grounding,
)
from app.services.systemmodel.models import Component, Dataflow, SystemModel, TrustZone


def _model(**kwargs) -> SystemModel:
    defaults = {
        "id": "p1",
        "version": 1,
        "parent_version": None,
        "trust_zones": [TrustZone(id="tz1", name="Internal", trust_rating=1)],
        "components": [Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")],
    }
    defaults.update(kwargs)
    return SystemModel(**defaults)


def _bridged(score: float = 0.03) -> list[BridgedTechnique]:
    return [BridgedTechnique(technique_id="T1", technique_name="X", matrix="enterprise", capec_ids=("CAPEC-1",), fused_score=score)]


def test_grounded_component_candidate_passes():
    model = _model()
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged())
    assert result.satisfied is True
    assert result.reason_code is None


def test_component_candidate_with_unknown_entity_fails_entity_binding():
    model = _model()
    candidate = CandidateThreat(id="ghost::spoofing::1.0.0", element_id="ghost", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged())
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_ENTITY_BINDING


def test_dataflow_candidate_with_unknown_flow_fails_entity_binding():
    model = _model()
    candidate = CandidateThreat(id="ghost-flow::tampering::1.0.0", element_id="ghost-flow", element_kind="dataflow", framework="stride", category="tampering", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged())
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_ENTITY_BINDING


def test_dataflow_candidate_with_unresolved_endpoint_fails_flow_binding():
    model = _model(
        components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")],
        dataflows=[Dataflow(id="f1", name="x", source_id="c1", destination_id="does-not-exist")],
    )
    candidate = CandidateThreat(id="f1::tampering::1.0.0", element_id="f1", element_kind="dataflow", framework="stride", category="tampering", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged())
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_FLOW_BINDING


def test_dataflow_candidate_with_both_endpoints_resolved_passes():
    model = _model(
        components=[
            Component(id="c1", name="A", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="B", kind="process", trust_zone_id="tz1"),
        ],
        dataflows=[Dataflow(id="f1", name="x", source_id="c1", destination_id="c2")],
    )
    candidate = CandidateThreat(id="f1::tampering::1.0.0", element_id="f1", element_kind="dataflow", framework="stride", category="tampering", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged())
    assert result.satisfied is True


def test_no_bridged_techniques_fails_citation():
    model = _model()
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, [])
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_CITATION


def test_bridged_techniques_all_below_threshold_fails_citation():
    model = _model()
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    result = check_grounding(candidate, model, _bridged(score=0.0001), citation_threshold=0.01)
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_CITATION


def test_at_least_one_technique_above_threshold_is_enough():
    model = _model()
    candidate = CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0")
    bridged = [
        BridgedTechnique(technique_id="T1", technique_name="Low", matrix="enterprise", capec_ids=("CAPEC-1",), fused_score=0.0001),
        BridgedTechnique(technique_id="T2", technique_name="High", matrix="enterprise", capec_ids=("CAPEC-2",), fused_score=0.05),
    ]
    result = check_grounding(candidate, model, bridged, citation_threshold=0.01)
    assert result.satisfied is True
