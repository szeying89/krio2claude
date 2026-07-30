import pytest

from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.enumeration.adjudication import (
    VERDICT_APPLICABLE,
    VERDICT_NOT_APPLICABLE,
    Adjudication,
)
from app.services.enumeration.agent import (
    AGENT_NAME,
    build_enumeration_agent,
    validate_enumeration_grounding,
)
from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.models import TechniqueChunk
from app.services.systemmodel.models import Asset, Component, Dataflow, SystemModel, TrustZone

RULESET = load_ruleset()

RICH_CHUNKS = [
    TechniqueChunk(id="T1499", matrix="enterprise", name="Endpoint DoS", tactics=("impact",), description="flood a target to exhaust resources denial of service", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-125",)}),
    TechniqueChunk(id="T1557", matrix="enterprise", name="Adversary-in-the-Middle", tactics=("collection",), description="tampering modify data in transit man in the middle", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-94",)}),
    TechniqueChunk(id="T1040", matrix="enterprise", name="Network Sniffing", tactics=("collection",), description="information disclosure sniffing collection of network traffic", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-158",)}),
    TechniqueChunk(id="T1078", matrix="enterprise", name="Valid Accounts", tactics=("initial-access",), description="spoofing identity impersonation using valid accounts", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-151",)}),
    TechniqueChunk(id="T1070", matrix="enterprise", name="Indicator Removal", tactics=("defense-evasion",), description="repudiation log tampering indicator removal", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-93",)}),
    TechniqueChunk(id="T1548", matrix="enterprise", name="Abuse Elevation Control Mechanism", tactics=("privilege-escalation",), description="privilege escalation exploitation elevate privileges", detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-233",)}),
]


def _model() -> SystemModel:
    return SystemModel(
        id="p1",
        version=1,
        parent_version=None,
        trust_zones=[
            TrustZone(id="dmz", name="DMZ", trust_rating=1),
            TrustZone(id="internal", name="Internal", trust_rating=3),
        ],
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gateway", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="User DB", kind="datastore", trust_zone_id="internal"),
            Component(id="isolated", name="Isolated Batch Job", kind="process", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f1", name="login", source_id="client", destination_id="gateway"),
            Dataflow(id="f2", name="query", source_id="gateway", destination_id="db"),
        ],
        assets=[
            Asset(id="a1", name="Passwords", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="db")
        ],
    )


def _registry_and_orchestrator(chunks):
    index = build_technique_index(chunks)
    registry = AgentRegistry()
    registry.register(build_enumeration_agent(RULESET, index))
    orchestrator = Orchestrator(registry, validate=validate_enumeration_grounding)
    return orchestrator


def test_every_candidate_is_either_adjudicated_or_rejected_never_both():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    adjudicated = result.output_artifacts["adjudicated_threats"]
    rejected = result.output_artifacts["rejection_log"]
    total = result.output_artifacts["candidate_count"]

    adjudicated_ids = {a.candidate_threat_id for a in adjudicated}
    rejected_ids = {r.candidate_threat_id for r in rejected}
    assert not (adjudicated_ids & rejected_ids)
    assert len(adjudicated_ids) + len(rejected_ids) == total


def test_unreachable_component_adjudicated_not_applicable_with_invalidation_condition():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    adjudicated = result.output_artifacts["adjudicated_threats"]
    isolated = [a for a in adjudicated if a.candidate_threat_id.startswith("isolated::")]
    assert isolated
    assert all(a.verdict == VERDICT_NOT_APPLICABLE for a in isolated)
    assert all(a.invalidation_condition is not None for a in isolated)


def test_reachable_grounded_candidates_are_applicable_with_real_evidence():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    adjudicated = result.output_artifacts["adjudicated_threats"]
    client_spoofing = next(a for a in adjudicated if a.candidate_threat_id == "client::spoofing::1.0.0")
    assert client_spoofing.verdict == VERDICT_APPLICABLE
    assert client_spoofing.evidence_ref in {c.id for c in RICH_CHUNKS}
    assert client_spoofing.invalidation_condition is None


def test_every_not_applicable_record_has_a_parseable_invalidation_condition():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    for adjudication in result.output_artifacts["adjudicated_threats"]:
        if adjudication.verdict == VERDICT_NOT_APPLICABLE:
            cond = adjudication.invalidation_condition
            assert cond is not None
            assert cond.kind
            assert cond.entity_id
            assert cond.description
        else:
            assert adjudication.invalidation_condition is None


def test_ungrounded_candidates_go_to_rejection_log_with_reason_code():
    # a KB corpus whose descriptions share no vocabulary with any STRIDE
    # category's search terms produces bridge results, if any, that never
    # clear the citation threshold for at least some categories
    sparse_chunks = [
        TechniqueChunk(
            id="Txxxx", matrix="enterprise", name="Irrelevant", tactics=("impact",),
            description="zzz qqq wwwww unrelated vocabulary entirely",
            detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-1",)},
        )
    ]
    orchestrator = _registry_and_orchestrator(sparse_chunks)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    rejected = result.output_artifacts["rejection_log"]
    assert len(rejected) > 0
    assert all(r.reason_code for r in rejected)


def test_orchestrator_gate_raises_when_an_ungrounded_record_slips_into_adjudicated():
    # simulates "agent-proposed threats face identical gating": regardless
    # of how a record ended up in adjudicated_threats, the orchestrator's
    # independent gate must still catch a missing/weak citation.
    bad_output = {
        "adjudicated_threats": [
            Adjudication(
                candidate_threat_id="fake::spoofing::1.0.0",
                verdict=VERDICT_APPLICABLE,
                rationale="fabricated",
                evidence_ref="",
                citation_score=0.0,
                invalidation_condition=None,
            )
        ],
        "rejection_log": [],
        "candidate_count": 1,
    }
    with pytest.raises(ValidationError):
        validate_enumeration_grounding(AGENT_NAME, bad_output)


def test_orchestrator_gate_passes_well_formed_output():
    good_output = {
        "adjudicated_threats": [
            Adjudication(
                candidate_threat_id="real::spoofing::1.0.0",
                verdict=VERDICT_APPLICABLE,
                rationale="grounded",
                evidence_ref="T1078",
                citation_score=0.05,
                invalidation_condition=None,
            )
        ],
        "rejection_log": [],
        "candidate_count": 1,
    }
    validate_enumeration_grounding(AGENT_NAME, good_output)  # must not raise


def test_orchestrator_gate_catches_candidate_in_both_lists():
    from app.services.enumeration.agent import RejectionLogEntry

    bad_output = {
        "adjudicated_threats": [
            Adjudication(
                candidate_threat_id="dup::spoofing::1.0.0",
                verdict=VERDICT_APPLICABLE,
                rationale="x",
                evidence_ref="T1",
                citation_score=0.05,
                invalidation_condition=None,
            )
        ],
        "rejection_log": [
            RejectionLogEntry(
                candidate_threat_id="dup::spoofing::1.0.0",
                element_id="c1",
                category="spoofing",
                reason_code="no_citation",
                detail="x",
            )
        ],
        "candidate_count": 1,
    }
    with pytest.raises(ValidationError):
        validate_enumeration_grounding(AGENT_NAME, bad_output)


def test_orchestrator_gate_catches_count_mismatch():
    bad_output = {"adjudicated_threats": [], "rejection_log": [], "candidate_count": 5}
    with pytest.raises(ValidationError):
        validate_enumeration_grounding(AGENT_NAME, bad_output)


def test_agent_recorded_every_deterministic_tool_call():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    result = orchestrator.invoke(AGENT_NAME, {"model": _model(), "atlas_enabled": False})
    tool_names = {call.tool_name for call in result.trajectory.tool_calls}
    assert "enumeration.enumerate_threats" in tool_names
    assert "enumeration.build_attack_graph" in tool_names
    assert "enumeration.check_grounding" in tool_names
    assert "enumeration.adjudicate" in tool_names


def test_cache_hit_on_identical_inputs():
    orchestrator = _registry_and_orchestrator(RICH_CHUNKS)
    model = _model()
    first = orchestrator.invoke(AGENT_NAME, {"model": model, "atlas_enabled": False})
    second = orchestrator.invoke(AGENT_NAME, {"model": model, "atlas_enabled": False})
    assert first.cache_hit is False
    assert second.cache_hit is True
