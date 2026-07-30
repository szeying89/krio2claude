import pytest

from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    compute_step_likelihood,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.models import TechniqueChunk
from app.services.systemmodel.models import (
    Asset,
    Component,
    Dataflow,
    DeclaredControl,
    SystemModel,
    TrustZone,
)

RULESET = load_ruleset()


def _chunk(id_, matrix, name, description, capec=("CAPEC-1",), tactics=("impact",)):
    return TechniqueChunk(
        id=id_,
        matrix=matrix,
        name=name,
        tactics=tactics,
        description=description,
        detection="",
        platforms=(),
        data_sources=(),
        relationships={"capec": capec} if capec else {},
    )


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


def _dataflow_candidates(model):
    candidates = enumerate_threats(model, RULESET)
    return [c for c in candidates if c.element_kind == "dataflow" and c.framework == "stride"]


def _build_graph(model, chunks):
    from app.services.enumeration.attack_graph import build_attack_graph

    index = build_technique_index(chunks)
    return build_attack_graph(model, _dataflow_candidates(model), index), index


# --- compute_step_likelihood -------------------------------------------


def test_external_position_more_likely_than_internal():
    external = compute_step_likelihood("external", "tampering", 0.03, "t", set(), "T1")
    internal = compute_step_likelihood("dmz", "tampering", 0.03, "t", set(), "T1")
    assert external > internal


def test_elevation_of_privilege_is_less_likely_than_information_disclosure():
    eop = compute_step_likelihood("external", "elevation_of_privilege", 0.03, "t", set(), "T1")
    info = compute_step_likelihood("external", "information_disclosure", 0.03, "t", set(), "T1")
    assert eop < info


def test_higher_fused_score_increases_likelihood():
    low = compute_step_likelihood("external", "tampering", 0.005, "t", set(), "T1")
    high = compute_step_likelihood("external", "tampering", 0.03, "t", set(), "T1")
    assert high > low


def test_control_presence_reduces_likelihood():
    uncontrolled = compute_step_likelihood("external", "tampering", 0.03, "t", set(), "T1")
    controlled = compute_step_likelihood("external", "tampering", 0.03, "t", {"t"}, "T1")
    assert controlled < uncontrolled


def test_intel_uplift_multiplies_likelihood():
    base = compute_step_likelihood("external", "tampering", 0.03, "t", set(), "T1")
    uplifted = compute_step_likelihood(
        "external", "tampering", 0.03, "t", set(), "T1", intel_uplift={"T1": 1.5}
    )
    assert uplifted > base


def test_likelihood_never_exceeds_one_or_drops_below_min():
    value = compute_step_likelihood(
        "external", "information_disclosure", 5.0, "t", set(), "T1", intel_uplift={"T1": 100.0}
    )
    assert 0 < value <= 1.0


# --- enumerate_paths: known small graph ---------------------------------


def _linear_model():
    return _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gateway", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="User DB", kind="datastore", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f1", name="login", source_id="client", destination_id="gateway"),
            Dataflow(id="f2", name="query", source_id="gateway", destination_id="db"),
        ],
        assets=[
            Asset(
                id="a1", name="Passwords", classification="pii", confidentiality=8, integrity=5,
                availability=5, owner_id="db",
            )
        ],
    )


CHUNKS = [
    _chunk("T1499", "enterprise", "Endpoint DoS", "denial of service flood exhaust resources", tactics=("impact",)),
    _chunk("T1557", "enterprise", "Adversary-in-the-Middle", "tampering modify data man in the middle", tactics=("collection",)),
    _chunk("T1040", "enterprise", "Network Sniffing", "information disclosure sniffing collection", tactics=("collection",)),
]


def test_known_graph_produces_expected_path_from_entry_to_crown_jewel():
    model = _linear_model()
    graph, _ = _build_graph(model, CHUNKS)
    result = enumerate_paths(graph, model)
    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.entry_point == "client"
    assert path.target == "db"
    assert len(path.steps) == 2
    assert path.steps[0].source_entity_id == "client"
    assert path.steps[1].target_entity_id == "db"


def test_path_tactic_sequence_reflects_technique_tactics():
    model = _linear_model()
    graph, _ = _build_graph(model, CHUNKS)
    result = enumerate_paths(graph, model)
    path = result.paths[0]
    assert len(path.tactic_sequence) == 2
    assert all(t != "unknown" for t in path.tactic_sequence)


def _client_to_app_model() -> SystemModel:
    return _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="app", name="App", kind="process", trust_zone_id="dmz"),
        ],
        dataflows=[Dataflow(id="f0", name="enter", source_id="client", destination_id="app")],
        assets=[
            Asset(
                id="a1", name="Secrets", classification="pii", confidentiality=8, integrity=5,
                availability=5, owner_id="app",
            )
        ],
    )


def test_deduplicates_interchangeable_technique_variants_per_hop():
    # multiple techniques can bridge the same hop; only the single most
    # likely one should appear as that hop's step, not one path per
    # technique combination
    model = _client_to_app_model()
    graph, _ = _build_graph(model, CHUNKS)
    result = enumerate_paths(graph, model)
    assert len(result.paths) == 1
    assert len(result.paths[0].steps) == 1


def test_higher_likelihood_technique_wins_the_hop():
    # both techniques are only ever bridged via the "denial_of_service"
    # category for this fixture (their descriptions share no vocabulary
    # with the other STRIDE categories' search terms); T1499's description
    # matches that category's query more strongly than T1040's, so it
    # should win the hop on retrieval relevance alone.
    model = _client_to_app_model()
    chunks = [
        _chunk("T1499", "enterprise", "Endpoint DoS", "denial of service flood exhaust resources"),
        _chunk("T1040", "enterprise", "Network Sniffing", "information disclosure sniffing collection"),
    ]
    graph, _ = _build_graph(model, chunks)
    result = enumerate_paths(graph, model)
    assert result.paths[0].steps[0].technique_id == "T1499"


def test_intel_uplift_can_flip_which_technique_wins_a_hop():
    model = _client_to_app_model()
    chunks = [
        _chunk("T1499", "enterprise", "Endpoint DoS", "denial of service flood exhaust resources"),
        _chunk("T1040", "enterprise", "Network Sniffing", "information disclosure sniffing collection"),
    ]
    graph, _ = _build_graph(model, chunks)
    without_uplift = enumerate_paths(graph, model)
    assert without_uplift.paths[0].steps[0].technique_id == "T1499"

    # T1040 loses on retrieval relevance alone; a strong intel uplift for
    # it (e.g. active exploitation seen in the wild) should flip the
    # winning technique for this hop without touching anything else in
    # the pipeline — exactly the seam Task 18's Intel Agent plugs into.
    with_uplift = enumerate_paths(graph, model, intel_uplift={"T1040": 10.0})
    assert with_uplift.paths[0].steps[0].technique_id == "T1040"


def test_control_presence_lowers_path_likelihood():
    model_without_control = _linear_model()
    graph1, _ = _build_graph(model_without_control, CHUNKS)
    result1 = enumerate_paths(graph1, model_without_control)

    model_with_control = _linear_model()
    model_with_control.declared_controls.append(
        DeclaredControl(id="ctrl-1", name="Encryption at rest", applies_to_ids=("db",))
    )
    graph2, _ = _build_graph(model_with_control, CHUNKS)
    result2 = enumerate_paths(graph2, model_with_control)

    assert result2.paths[0].aggregate_likelihood < result1.paths[0].aggregate_likelihood


# --- caps -----------------------------------------------------------------


def test_max_depth_excludes_deep_paths():
    model = _model(
        components=[
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="a", name="A", kind="process", trust_zone_id="dmz"),
            Component(id="b", name="B", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="DB", kind="datastore", trust_zone_id="internal"),
        ],
        dataflows=[
            Dataflow(id="f0", name="x", source_id="client", destination_id="a"),
            Dataflow(id="f1", name="x", source_id="a", destination_id="b"),
            Dataflow(id="f2", name="x", source_id="b", destination_id="db"),
        ],
        assets=[
            Asset(id="a1", name="Secrets", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="db")
        ],
    )
    graph, _ = _build_graph(model, CHUNKS)
    result = enumerate_paths(graph, model, max_depth=2)
    assert result.paths == ()  # the only path to db is 3 hops long


def test_k_per_target_caps_and_reports():
    # a fan of 5 parallel entry->target dataflows via distinct intermediate
    # nodes, each a distinct path of equal length, forces > k options
    components = [
        Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
        Component(id="db", name="DB", kind="datastore", trust_zone_id="internal"),
    ]
    dataflows = []
    for i in range(5):
        mid = f"mid{i}"
        components.append(Component(id=mid, name=f"Mid {i}", kind="process", trust_zone_id="dmz"))
        dataflows.append(Dataflow(id=f"in{i}", name="x", source_id="client", destination_id=mid))
        dataflows.append(Dataflow(id=f"out{i}", name="x", source_id=mid, destination_id="db"))
    model = _model(
        components=components,
        dataflows=dataflows,
        assets=[Asset(id="a1", name="Secrets", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="db")],
    )
    graph, _ = _build_graph(model, CHUNKS)
    result = enumerate_paths(graph, model, k_per_target=2)
    assert len(result.paths) == 2
    assert result.capped is True


def test_search_budget_breach_raises():
    model = _linear_model()
    graph, _ = _build_graph(model, CHUNKS)
    with pytest.raises(PathEnumerationBudgetExceededError):
        enumerate_paths(graph, model, search_budget=0)


# --- stability / determinism ---------------------------------------------


def test_path_ids_and_ordering_stable_across_runs():
    model = _linear_model()
    graph, _ = _build_graph(model, CHUNKS)
    first = enumerate_paths(graph, model)
    second = enumerate_paths(graph, model)
    assert [p.id for p in first.paths] == [p.id for p in second.paths]


def test_fan_out_stress_graph_completes_within_default_budget():
    components = [
        Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
        Component(id="hub", name="Hub", kind="process", trust_zone_id="dmz"),
        Component(id="db", name="DB", kind="datastore", trust_zone_id="internal"),
    ]
    dataflows = [
        Dataflow(id="in", name="x", source_id="client", destination_id="hub"),
        Dataflow(id="out", name="x", source_id="hub", destination_id="db"),
    ]
    chunks = [
        _chunk(f"T{i:04d}", "enterprise", f"Technique {i}", "tampering modify data man in the middle")
        for i in range(30)
    ]
    model = _model(
        components=components,
        dataflows=dataflows,
        assets=[Asset(id="a1", name="Secrets", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="db")],
    )
    graph, _ = _build_graph(model, chunks)
    result = enumerate_paths(graph, model, k_per_target=5)
    assert len(result.paths) >= 1
