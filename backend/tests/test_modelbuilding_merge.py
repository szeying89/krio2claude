from app.services.mermaid.models import (
    ArrowType,
    Edge,
    Node,
    NodeShape,
    ParsedDiagram,
    Subgraph,
)
from app.services.modelbuilding.merge import ModelBuilder, infer_kind_from_shape, normalize_name
from app.services.modelbuilding.prose_extractor import (
    ProseActor,
    ProseAsset,
    ProseComponent,
    ProseDeclaredControl,
    ProseExtractionResult,
    ProseFlow,
    ProseSourceSpan,
    ProseTrustZone,
)


def _span(start: int = 1, end: int = 1) -> ProseSourceSpan:
    return ProseSourceSpan(start_line=start, end_line=end)


def test_normalize_name_collapses_whitespace_and_case():
    assert normalize_name("  Auth   Service ") == "auth service"


def test_infer_kind_from_shape_heuristic():
    assert infer_kind_from_shape(NodeShape.CYLINDER) == "datastore"
    assert infer_kind_from_shape(NodeShape.CIRCLE) == "external_entity"
    assert infer_kind_from_shape(NodeShape.STADIUM) == "external_entity"
    assert infer_kind_from_shape(NodeShape.RECTANGLE) == "process"
    assert infer_kind_from_shape(NodeShape.DEFAULT) == "process"


def _diagram() -> ParsedDiagram:
    return ParsedDiagram(
        diagram_type="flowchart",
        direction="TD",
        nodes=(
            Node(id="U", label="User", shape=NodeShape.CIRCLE, line=2),
            Node(id="A", label="Auth Service", shape=NodeShape.RECTANGLE, line=3),
            Node(id="D", label="User DB", shape=NodeShape.CYLINDER, line=4),
        ),
        edges=(
            Edge(source="U", target="A", arrow=ArrowType.ARROW, bidirectional=False, label="login", line=5),
            Edge(source="A", target="D", arrow=ArrowType.ARROW, bidirectional=False, label="query", line=6),
        ),
        subgraphs=(Subgraph(id="internal", title="Internal Zone", node_ids=("A", "D"), subgraph_ids=(), line=1),),
    )


def test_add_diagram_builds_components_actors_flows_and_trust_zone():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())

    assert {c.name for c in builder.draft.components} == {"Auth Service", "User DB"}
    assert {a.name for a in builder.draft.actors} == {"User"}
    assert len(builder.draft.flows) == 2

    auth = next(c for c in builder.draft.components if c.name == "Auth Service")
    db = next(c for c in builder.draft.components if c.name == "User DB")
    assert db.kind == "datastore"
    assert auth.kind == "process"

    zone = builder.draft.trust_zones[0]
    assert zone.name == "Internal Zone"
    assert auth.trust_zone_id == zone.id
    assert db.trust_zone_id == zone.id


def test_add_diagram_dedupes_mermaid_nodes_by_name_across_diagrams():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    second = ParsedDiagram(
        diagram_type="flowchart",
        direction="TD",
        nodes=(Node(id="X", label="Auth Service", shape=NodeShape.RECTANGLE, line=1),),
        edges=(),
        subgraphs=(),
    )
    builder.add_diagram("doc2", second)
    assert len([c for c in builder.draft.components if c.name == "Auth Service"]) == 1


def test_prose_only_component_added_with_inference_assumption():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        components=[
            ProseComponent(
                name="Payment Processor", kind="process", confidence=0.8, source_span=_span(10, 10)
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)

    assert any(c.name == "Payment Processor" for c in builder.draft.components)
    added = next(c for c in builder.draft.components if c.name == "Payment Processor")
    assert added.source == "prose"
    assumption = next(a for a in builder.draft.assumptions if a.subject_id == added.id)
    assert assumption.kind == "inference"
    assert assumption.confidence == 0.8


def test_prose_merges_technology_tags_onto_existing_mermaid_component():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        components=[
            ProseComponent(
                name="Auth Service",
                kind="process",
                technology_tags=["OAuth2", "JWT"],
                confidence=0.9,
                source_span=_span(5, 5),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)

    auth = next(c for c in builder.draft.components if c.name == "Auth Service")
    assert auth.technology_tags == ("OAuth2", "JWT")
    assert auth.source == "merged"
    assert len(builder.draft.components) == 2  # not duplicated


def test_prose_kind_conflict_with_mermaid_shape_logs_conflict_and_keeps_mermaid_kind():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        components=[
            ProseComponent(
                name="Auth Service", kind="datastore", confidence=0.7, source_span=_span(5, 5)
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)

    auth = next(c for c in builder.draft.components if c.name == "Auth Service")
    assert auth.kind == "process"  # mermaid shape wins
    conflicts = [a for a in builder.draft.assumptions if a.kind == "conflict"]
    assert len(conflicts) == 1
    assert conflicts[0].subject_id == auth.id


def test_prose_asset_with_no_classification_defaults_and_logs_default_assumption():
    builder = ModelBuilder()
    extraction = ProseExtractionResult(
        assets=[ProseAsset(name="Credit Card Number", confidence=0.9, source_span=_span(7, 7))]
    )
    builder.add_prose_extraction("doc1", extraction)

    asset = builder.draft.assets[0]
    assert asset.classification == "unclassified"
    defaults = [a for a in builder.draft.assumptions if a.kind == "default"]
    assert len(defaults) == 1
    assert defaults[0].subject_id == asset.id


def test_prose_asset_with_stated_classification_is_kept_verbatim():
    builder = ModelBuilder()
    extraction = ProseExtractionResult(
        assets=[
            ProseAsset(
                name="Credit Card Number",
                classification="PCI",
                confidence=0.9,
                source_span=_span(7, 7),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)
    assert builder.draft.assets[0].classification == "PCI"
    assert not any(a.kind == "default" for a in builder.draft.assumptions)


def test_prose_flow_matching_existing_mermaid_flow_enriches_protocol():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        flows=[
            ProseFlow(
                source_name="User",
                target_name="Auth Service",
                protocol="HTTPS",
                authenticated=True,
                confidence=0.85,
                source_span=_span(5, 5),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)

    assert len(builder.draft.flows) == 2  # merged, not duplicated
    flow = next(f for f in builder.draft.flows if f.label == "login")
    assert flow.protocol == "HTTPS"
    assert flow.authenticated is True
    assert flow.source == "merged"


def test_prose_flow_conflicting_protocol_logs_conflict_and_keeps_first_value():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        flows=[
            ProseFlow(
                source_name="User",
                target_name="Auth Service",
                protocol="HTTPS",
                confidence=0.8,
                source_span=_span(5, 5),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)
    # a second, conflicting statement about the same flow
    extraction2 = ProseExtractionResult(
        flows=[
            ProseFlow(
                source_name="User",
                target_name="Auth Service",
                protocol="HTTP",
                confidence=0.6,
                source_span=_span(9, 9),
            )
        ]
    )
    builder.add_prose_extraction("doc2", extraction2)

    flow = next(f for f in builder.draft.flows if f.label == "login")
    assert flow.protocol == "HTTPS"  # first value kept
    assert any(a.kind == "conflict" and a.subject_id == flow.id for a in builder.draft.assumptions)


def test_prose_only_flow_creates_stub_endpoints_and_logs_inference():
    builder = ModelBuilder()
    extraction = ProseExtractionResult(
        flows=[
            ProseFlow(
                source_name="Mobile App",
                target_name="Notification Service",
                confidence=0.7,
                source_span=_span(3, 3),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)

    assert len(builder.draft.flows) == 1
    names = {c.name for c in builder.draft.components} | {a.name for a in builder.draft.actors}
    assert {"Mobile App", "Notification Service"} <= names
    assert any(a.kind == "inference" for a in builder.draft.assumptions)


def test_prose_actor_kind_is_always_external_entity():
    builder = ModelBuilder()
    extraction = ProseExtractionResult(
        actors=[ProseActor(name="Third-Party Bank API", confidence=0.9, source_span=_span(1, 1))]
    )
    builder.add_prose_extraction("doc1", extraction)
    actor = builder.draft.actors[0]
    assert actor.kind == "external_entity"


def test_prose_trust_zone_merges_into_existing_mermaid_zone_by_name():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        trust_zones=[
            ProseTrustZone(
                name="Internal Zone",
                member_names=["User DB"],
                confidence=0.8,
                source_span=_span(1, 1),
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)
    assert len(builder.draft.trust_zones) == 1
    zone = builder.draft.trust_zones[0]
    assert zone.source == "merged"


def test_prose_only_trust_zone_is_added_with_inference_assumption():
    builder = ModelBuilder()
    extraction = ProseExtractionResult(
        trust_zones=[
            ProseTrustZone(name="DMZ", member_names=[], confidence=0.6, source_span=_span(2, 2))
        ]
    )
    builder.add_prose_extraction("doc1", extraction)
    assert len(builder.draft.trust_zones) == 1
    assert builder.draft.trust_zones[0].source == "prose"
    assert any(a.kind == "inference" for a in builder.draft.assumptions)


def test_declared_control_resolves_applies_to_by_name():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    extraction = ProseExtractionResult(
        declared_controls=[
            ProseDeclaredControl(
                name="MFA", applies_to_names=["Auth Service"], confidence=0.9, source_span=_span(4, 4)
            )
        ]
    )
    builder.add_prose_extraction("doc1", extraction)
    control = builder.draft.declared_controls[0]
    auth = next(c for c in builder.draft.components if c.name == "Auth Service")
    assert control.applies_to_ids == (auth.id,)


def test_element_trust_zone_lookup():
    builder = ModelBuilder()
    builder.add_diagram("doc1", _diagram())
    auth = next(c for c in builder.draft.components if c.name == "Auth Service")
    zone = builder.draft.trust_zones[0]
    assert builder.element_trust_zone(auth.id) == zone.id
    assert builder.element_trust_zone("nonexistent") is None
