from app.services.modelbuilding.completeness import check_completeness
from app.services.modelbuilding.merge import ModelBuilder
from app.services.modelbuilding.models import (
    ModelAsset,
    ModelComponent,
    ModelFlow,
    ModelTrustZone,
    SourceSpan,
)


def _span() -> SourceSpan:
    return SourceSpan(document_id="doc1", start_line=1, end_line=1)


def test_no_findings_for_a_clean_model():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Auth Service",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="c2",
            name="Auth DB",
            kind="datastore",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="c2",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_dangling_flow_detected():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Auth Service",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="does-not-exist",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert [f.kind for f in findings] == ["dangling_flow"]
    assert findings[0].subject_id == "f1"


def test_sourceless_sink_detected_for_datastore_with_no_incoming_flow():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="db1",
            name="User DB",
            kind="datastore",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert [f.kind for f in findings] == ["sourceless_sink"]
    assert findings[0].subject_id == "db1"


def test_datastore_with_incoming_flow_is_not_a_sourceless_sink():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="App",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="db1",
            name="User DB",
            kind="datastore",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="db1",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_unclassified_asset_detected():
    builder = ModelBuilder()
    builder.draft.assets.append(
        ModelAsset(
            id="a1",
            name="Some Data",
            classification="unclassified",
            owner_id=None,
            source="prose",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert [f.kind for f in findings] == ["unclassified_asset"]
    assert findings[0].subject_id == "a1"


def test_classified_asset_produces_no_finding():
    builder = ModelBuilder()
    builder.draft.assets.append(
        ModelAsset(
            id="a1",
            name="Credit Card",
            classification="PCI",
            owner_id=None,
            source="prose",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_untagged_boundary_crossing_detected():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Public API",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="c2",
            name="Internal Service",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.trust_zones.append(
        ModelTrustZone(
            id="z1", name="Internal Zone", member_ids=("c2",), source="mermaid", source_spans=(_span(),)
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="c2",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert [f.kind for f in findings] == ["untagged_boundary_crossing"]


def test_boundary_crossing_with_protocol_stated_is_not_flagged():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Public API",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="c2",
            name="Internal Service",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.trust_zones.append(
        ModelTrustZone(
            id="z1", name="Internal Zone", member_ids=("c2",), source="mermaid", source_spans=(_span(),)
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="c2",
            label="",
            protocol="HTTPS",
            authenticated=True,
            encrypted=True,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_flow_within_same_zone_is_not_a_boundary_crossing():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Service A",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="c2",
            name="Service B",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.trust_zones.append(
        ModelTrustZone(
            id="z1",
            name="Internal Zone",
            member_ids=("c1", "c2"),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="c2",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_flow_between_two_unzoned_elements_is_not_a_boundary_crossing():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="c1",
            name="Service A",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.components.append(
        ModelComponent(
            id="c2",
            name="Service B",
            kind="process",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    builder.draft.flows.append(
        ModelFlow(
            id="f1",
            source_id="c1",
            target_id="c2",
            label="",
            protocol=None,
            authenticated=None,
            encrypted=None,
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    findings = check_completeness(builder.draft, builder)
    assert findings == []


def test_draft_needs_input_property_reflects_findings():
    builder = ModelBuilder()
    builder.draft.components.append(
        ModelComponent(
            id="db1",
            name="User DB",
            kind="datastore",
            trust_zone_id=None,
            technology_tags=(),
            source="mermaid",
            source_spans=(_span(),),
        )
    )
    assert builder.draft.needs_input is False
    builder.draft.completeness_findings = check_completeness(builder.draft, builder)
    assert builder.draft.needs_input is True
