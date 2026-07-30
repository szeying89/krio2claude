from app.services.mermaid.parser import parse_diagram
from app.services.systemmodel.mermaid_render import render_system_model
from app.services.systemmodel.models import Component, Dataflow, SystemModel, TrustZone


def _model() -> SystemModel:
    return SystemModel(
        id="proj1",
        version=1,
        parent_version=None,
        trust_zones=[TrustZone(id="tz-1", name="Internal Zone", trust_rating=1)],
        components=[
            Component(id="component-1", name="Auth Service", kind="process", trust_zone_id="tz-1"),
            Component(id="component-2", name="User DB", kind="datastore", trust_zone_id="tz-1"),
            Component(id="actor-1", name="User", kind="external_entity", trust_zone_id="tz-1"),
        ],
        dataflows=[
            Dataflow(id="flow-1", name="login", source_id="actor-1", destination_id="component-1")
        ],
    )


def test_render_produces_reparseable_mermaid():
    source = render_system_model(_model())
    diagram = parse_diagram(source)
    assert {n.label for n in diagram.nodes} == {"Auth Service", "User DB", "User"}
    assert len(diagram.edges) == 1
    assert diagram.edges[0].label == "login"


def test_render_groups_components_by_trust_zone_subgraph():
    source = render_system_model(_model())
    diagram = parse_diagram(source)
    assert len(diagram.subgraphs) == 1
    assert diagram.subgraphs[0].title == "Internal Zone"
    assert len(diagram.subgraphs[0].node_ids) == 3


def test_render_is_deterministic():
    model = _model()
    assert render_system_model(model) == render_system_model(model)


def test_hyphenated_ids_are_sanitized_for_mermaid():
    source = render_system_model(_model())
    assert "component-1" not in source
    assert "component_1" in source


def test_datastore_uses_cylinder_shape():
    source = render_system_model(_model())
    assert "component_2[(User DB)]" in source


def test_external_entity_uses_circle_shape():
    source = render_system_model(_model())
    assert "actor_1((User))" in source
