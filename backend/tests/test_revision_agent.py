import pytest

from app.models.enums import BusinessCriticality
from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.models import TechniqueChunk
from app.services.revision.agent import (
    AGENT_NAME,
    build_revision_agent,
    validate_revision_grounding,
)
from app.services.revision.models import (
    AdjudicationSummary,
    RevisionSnapshot,
    ThreatLandscapeCurrency,
)
from app.services.systemmodel.models import Asset, Component, Dataflow, SystemModel, TrustZone

RULESET = load_ruleset()
CHUNKS = [
    TechniqueChunk(
        id="T1499", matrix="enterprise", name="Endpoint Denial of Service", tactics=("impact",),
        description="flood a target host to exhaust resources deny service tampering",
        detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-125",)},
    ),
]
INDEX = build_technique_index(CHUNKS)
TECHNIQUES_BY_ID = {c.id: c for c in CHUNKS}


def _model() -> SystemModel:
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="dmz", name="DMZ", trust_rating=1)],
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gw", name="Gateway", kind="process", trust_zone_id="dmz"),
        ],
        dataflows=[Dataflow(id="f1", name="login", source_id="client", destination_id="gw")],
        assets=[
            Asset(id="a1", name="Data", classification="confidential", confidentiality=8, integrity=5, availability=5, owner_id="gw")
        ],
    )


def _input_artifacts(articles=()):
    return {
        "model": _model(),
        "ruleset": RULESET,
        "index": INDEX,
        "techniques_by_id": TECHNIQUES_BY_ID,
        "d3fend_catalog": [],
        "cri_statements": [],
        "regulatory_documents": {},
        "tier": None,
        "business_criticality": BusinessCriticality.HIGH,
        "atlas_enabled": False,
        "articles": list(articles),
        "kb_fetched_at": None,
        "cri_fetched_at": None,
    }


def test_revision_agent_produces_a_snapshot_through_the_orchestrator():
    registry = AgentRegistry()
    registry.register(build_revision_agent())
    orchestrator = Orchestrator(registry, validate=validate_revision_grounding)

    result = orchestrator.invoke(AGENT_NAME, _input_artifacts())
    assert result.status == "complete"
    snapshot = result.output_artifacts["snapshot"]
    assert isinstance(snapshot, RevisionSnapshot)
    assert snapshot.paths


def test_validate_gate_rejects_a_hand_constructed_ungrounded_adjudication():
    fabricated = RevisionSnapshot(
        paths=(), adjudications=(AdjudicationSummary("c1", "applicable", 0.0),), rejection_count=0,
        risk_total_score=0.0, csf_rollup=(),
        confidence=1.0,
        currency=ThreatLandscapeCurrency(None, None, 0, None),
    )
    with pytest.raises(ValidationError):
        validate_revision_grounding("revision", {"snapshot": fabricated})


def test_validate_gate_passes_well_formed_output_through_untouched():
    ok = RevisionSnapshot(
        paths=(), adjudications=(AdjudicationSummary("c1", "applicable", 1.0),), rejection_count=0,
        risk_total_score=0.0, csf_rollup=(),
        confidence=1.0,
        currency=ThreatLandscapeCurrency(None, None, 0, None),
    )
    validate_revision_grounding("revision", {"snapshot": ok})


def test_invalidation_graph_reaches_the_same_downstream_set_regardless_of_trigger_artifact_type():
    """Task 19's plan text: "the invalidation graph re-runs the same
    minimal downstream set as it would for a clarification or review-item
    change." Two upstream triggers ("intel" and a stand-in "clarification"
    type) each feed a different first-hop agent, but both cascade through
    to the exact same downstream agent — demonstrating the invalidation
    graph (Task 1b) treats any artifact-type change identically, with no
    special-casing for intel specifically.
    """

    def _noop_handler(ctx: AgentContext) -> dict:
        return {}

    registry = AgentRegistry()
    registry.register(build_revision_agent())  # inputs=("system_model", "intel"), outputs=("snapshot",)
    registry.register(
        AgentSpec(
            name="clarification_intake",
            input_artifact_types=("system_model", "clarification"),
            output_artifact_types=("snapshot",),
            handler=_noop_handler,
        )
    )
    registry.register(
        AgentSpec(
            name="risk_summary",
            input_artifact_types=("snapshot",),
            output_artifact_types=("risk_summary",),
            handler=_noop_handler,
        )
    )
    orchestrator = Orchestrator(registry)

    affected_via_intel = orchestrator.compute_affected({"intel"})
    affected_via_clarification = orchestrator.compute_affected({"clarification"})

    assert affected_via_intel == {AGENT_NAME, "risk_summary"}
    assert affected_via_clarification == {"clarification_intake", "risk_summary"}
    # same downstream reach (one direct hit + the same cascaded consumer) for either trigger
    assert len(affected_via_intel) == len(affected_via_clarification)
    assert "risk_summary" in affected_via_intel and "risk_summary" in affected_via_clarification
