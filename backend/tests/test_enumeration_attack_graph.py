import networkx as nx
import pytest

from app.services.enumeration.attack_graph import (
    AttackGraphBudgetExceededError,
    PrivilegeLevel,
    build_attack_graph,
    check_authentication,
    check_boundary_crossing,
    check_exposure,
    check_reachability,
    check_required_privilege,
)
from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.engine import CandidateThreat, enumerate_threats
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.models import TechniqueChunk
from app.services.systemmodel.models import Asset, Component, Dataflow, SystemModel, TrustZone

RULESET = load_ruleset()


def _chunk(id_, matrix, name, description, capec=("CAPEC-1",)):
    return TechniqueChunk(
        id=id_,
        matrix=matrix,
        name=name,
        tactics=("impact",),
        description=description,
        detection="",
        platforms=(),
        data_sources=(),
        relationships={"capec": capec} if capec else {},
    )


DEFAULT_CHUNKS = [
    _chunk("T1499", "enterprise", "Endpoint DoS", "denial of service flood exhaust resources"),
    _chunk("T1557", "enterprise", "Adversary-in-the-Middle", "tampering modify data man in the middle"),
    _chunk("T1040", "enterprise", "Network Sniffing", "information disclosure sniffing collection"),
    _chunk("T1548", "enterprise", "Abuse Elevation Control Mechanism", "privilege escalation exploitation elevate privileges"),
]


def _model(**kwargs) -> SystemModel:
    defaults = {
        "id": "p1",
        "version": 1,
        "parent_version": None,
        "trust_zones": [
            TrustZone(id="dmz", name="DMZ", trust_rating=1),
            TrustZone(id="internal", name="Internal", trust_rating=3),
        ],
    }
    defaults.update(kwargs)
    return SystemModel(**defaults)


def _dataflow_candidates(model) -> list[CandidateThreat]:
    candidates = enumerate_threats(model, RULESET)
    return [c for c in candidates if c.element_kind == "dataflow" and c.framework == "stride"]


# --- Precondition predicates ------------------------------------------------


def test_check_reachability_true_when_flow_exists():
    flow = Dataflow(id="f1", name="x", source_id="a", destination_id="b")
    assert check_reachability(flow).satisfied is True


def test_check_reachability_false_when_no_flow():
    assert check_reachability(None).satisfied is False


def test_check_exposure_true_for_internal_foothold_regardless_of_source():
    flow = Dataflow(id="f1", name="x", source_id="internal-thing", destination_id="b")
    result = check_exposure(flow, from_external=False, external_actor_ids=set())
    assert result.satisfied is True


def test_check_exposure_true_when_source_is_external_actor():
    flow = Dataflow(id="f1", name="x", source_id="client", destination_id="b")
    result = check_exposure(flow, from_external=True, external_actor_ids={"client"})
    assert result.satisfied is True


def test_check_exposure_false_when_first_hop_not_from_external_actor():
    flow = Dataflow(id="f1", name="x", source_id="something-else", destination_id="b")
    result = check_exposure(flow, from_external=True, external_actor_ids={"client"})
    assert result.satisfied is False


def test_check_authentication_true_when_flow_not_authenticated():
    flow = Dataflow(id="f1", name="x", source_id="a", destination_id="b", authenticated=False)
    assert check_authentication(flow, PrivilegeLevel.NONE, "tampering").satisfied is True


def test_check_authentication_spoofing_bypasses_auth_requirement():
    flow = Dataflow(id="f1", name="x", source_id="a", destination_id="b", authenticated=True)
    assert check_authentication(flow, PrivilegeLevel.NONE, "spoofing").satisfied is True


def test_check_authentication_satisfied_with_prior_privilege():
    flow = Dataflow(id="f1", name="x", source_id="a", destination_id="b", authenticated=True)
    assert check_authentication(flow, PrivilegeLevel.USER, "tampering").satisfied is True


def test_check_authentication_blocked_without_privilege_or_spoofing():
    flow = Dataflow(id="f1", name="x", source_id="a", destination_id="b", authenticated=True)
    assert check_authentication(flow, PrivilegeLevel.NONE, "tampering").satisfied is False


def test_check_required_privilege_non_elevation_always_satisfied():
    assert check_required_privilege("tampering", PrivilegeLevel.NONE).satisfied is True


def test_check_required_privilege_elevation_requires_foothold():
    assert check_required_privilege("elevation_of_privilege", PrivilegeLevel.NONE).satisfied is False
    assert check_required_privilege("elevation_of_privilege", PrivilegeLevel.USER).satisfied is True


def test_check_boundary_crossing_detects_zone_change():
    assert check_boundary_crossing("dmz", "internal").detail == "crosses a trust-zone boundary"
    assert check_boundary_crossing("dmz", "dmz").detail == "stays within the same trust zone"


# --- Graph construction ------------------------------------------------


def test_unreachable_transitions_produce_no_edges():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gateway", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="isolated", name="Isolated Service", kind="process", trust_zone_id="internal"),
        ],
        dataflows=[Dataflow(id="f1", name="login", source_id="client", destination_id="gateway")],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    entity_ids = {n.entity_id for n in result.graph.nodes}
    assert "isolated" not in entity_ids


def test_out_of_scope_entities_never_appear_as_nodes():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(
                id="scada", name="SCADA Historian", kind="datastore", trust_zone_id="internal",
                out_of_scope=True,
            ),
        ],
        dataflows=[Dataflow(id="f1", name="poll", source_id="client", destination_id="scada")],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    assert "scada" not in {n.entity_id for n in result.graph.nodes}


def test_graph_is_acyclic_even_with_a_dataflow_cycle():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="a", name="Service A", kind="process", trust_zone_id="internal"),
            Component(id="b", name="Service B", kind="process", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f0", name="enter", source_id="client", destination_id="a"),
            Dataflow(id="f1", name="a-to-b", source_id="a", destination_id="b"),
            Dataflow(id="f2", name="b-to-a", source_id="b", destination_id="a"),
        ],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    assert nx.is_directed_acyclic_graph(nx.DiGraph(result.graph))


def test_privilege_never_decreases_along_any_edge():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
            Component(id="admin", name="Admin Console", kind="process", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f0", name="enter", source_id="client", destination_id="app"),
            Dataflow(id="f1", name="escalate", source_id="app", destination_id="admin"),
        ],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    for u, v in result.graph.edges():
        assert v.privilege_level >= u.privilege_level


def test_node_budget_breach_raises_rather_than_truncating():
    components = [Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz")]
    dataflows = []
    prev = "client"
    for i in range(10):
        cid = f"svc{i}"
        components.append(Component(id=cid, name=f"Service {i}", kind="process", trust_zone_id="dmz"))
        dataflows.append(Dataflow(id=f"f{i}", name="call", source_id=prev, destination_id=cid))
        prev = cid
    model = _model(components=components, dataflows=dataflows)
    index = build_technique_index(DEFAULT_CHUNKS)
    with pytest.raises(AttackGraphBudgetExceededError) as exc_info:
        build_attack_graph(model, _dataflow_candidates(model), index, node_budget=3)
    assert exc_info.value.kind == "node"


def test_edge_budget_breach_raises_rather_than_truncating():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
        ],
        dataflows=[Dataflow(id="f0", name="enter", source_id="client", destination_id="app")],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    with pytest.raises(AttackGraphBudgetExceededError) as exc_info:
        build_attack_graph(model, _dataflow_candidates(model), index, edge_budget=1)
    assert exc_info.value.kind == "edge"


def test_entry_points_are_external_actors_and_crown_jewels_are_asset_owners():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="DB", kind="datastore", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f0", name="enter", source_id="client", destination_id="app"),
            Dataflow(id="f1", name="query", source_id="app", destination_id="db"),
        ],
        assets=[
            Asset(id="a1", name="Secrets", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="db")
        ],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    assert result.entry_points == ("client",)
    assert result.crown_jewels == ("db",)


def test_edges_carry_citation_and_preconditions():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
        ],
        dataflows=[Dataflow(id="f0", name="enter", source_id="client", destination_id="app")],
    )
    index = build_technique_index(DEFAULT_CHUNKS)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    _, _, data = next(iter(result.graph.edges(data=True)))
    edge = data["data"]
    assert edge.citation != ""
    assert {p.kind for p in edge.preconditions} == {
        "reachability", "exposure", "authentication", "required_privilege", "boundary_crossing"
    }
    assert edge.candidate_threat_id != ""


def test_no_matching_technique_produces_no_edge():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
        ],
        dataflows=[Dataflow(id="f0", name="enter", source_id="client", destination_id="app")],
    )
    # a KB corpus with zero CAPEC-mapped techniques means the bridge can
    # never surface anything, so no edge should ever be created
    uncited_chunks = [
        TechniqueChunk(
            id="Tnone", matrix="enterprise", name="Uncited", tactics=("impact",),
            description="denial of service flood exhaust resources",
            detection="", platforms=(), data_sources=(), relationships={},
        )
    ]
    index = build_technique_index(uncited_chunks)
    result = build_attack_graph(model, _dataflow_candidates(model), index)
    assert result.graph.number_of_edges() == 0
