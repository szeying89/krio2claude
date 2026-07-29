from app.services.modelbuilding.models import (
    DeclaredControl,
    ModelActor,
    ModelAsset,
    ModelComponent,
    ModelFlow,
    ModelTrustZone,
    SourceSpan,
    SystemModelDraft,
)
from app.services.systemmodel.freeze import UNCLASSIFIED_ZONE_ID, freeze_draft


def _span() -> SourceSpan:
    return SourceSpan(document_id="doc1", start_line=1, end_line=1)


def test_freeze_empty_draft_produces_empty_model():
    model = freeze_draft(SystemModelDraft(), model_id="proj1")
    assert model.id == "proj1"
    assert model.version == 1
    assert model.parent_version is None
    assert model.components == []
    assert model.trust_zones == []


def test_freeze_zoned_component_keeps_its_zone():
    draft = SystemModelDraft(
        trust_zones=[
            ModelTrustZone(
                id="zone1", name="Internal", member_ids=("c1",), source="mermaid", source_spans=(_span(),)
            )
        ],
        components=[
            ModelComponent(
                id="c1",
                name="Auth Service",
                kind="process",
                trust_zone_id="zone1",
                technology_tags=(),
                source="mermaid",
                source_spans=(_span(),),
            )
        ],
    )
    model = freeze_draft(draft, model_id="proj1")
    assert len(model.trust_zones) == 1
    component = model.components[0]
    assert component.trust_zone_id == "zone1"


def test_freeze_unzoned_component_goes_to_unclassified_zone_and_is_noted():
    draft = SystemModelDraft(
        components=[
            ModelComponent(
                id="c1",
                name="Auth Service",
                kind="process",
                trust_zone_id=None,
                technology_tags=(),
                source="prose",
                source_spans=(_span(),),
            )
        ]
    )
    model = freeze_draft(draft, model_id="proj1")
    assert any(z.id == UNCLASSIFIED_ZONE_ID for z in model.trust_zones)
    component = model.components[0]
    assert component.trust_zone_id == UNCLASSIFIED_ZONE_ID
    assert any("Unclassified Zone" in note for note in model.change_summary)


def test_freeze_actor_always_goes_to_unclassified_zone():
    draft = SystemModelDraft(
        actors=[ModelActor(id="a1", name="User", kind="external_entity", source="mermaid", source_spans=(_span(),))]
    )
    model = freeze_draft(draft, model_id="proj1")
    actor_component = next(c for c in model.components if c.id == "a1")
    assert actor_component.trust_zone_id == UNCLASSIFIED_ZONE_ID
    assert actor_component.kind == "external_entity"


def test_freeze_maps_flow_fields():
    draft = SystemModelDraft(
        flows=[
            ModelFlow(
                id="f1",
                source_id="a",
                target_id="b",
                label="login",
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
                source="mermaid",
                source_spans=(_span(),),
            )
        ]
    )
    model = freeze_draft(draft, model_id="proj1")
    flow = model.dataflows[0]
    assert flow.source_id == "a"
    assert flow.destination_id == "b"
    assert flow.protocol == "HTTPS"
    assert flow.authenticated is True
    assert flow.encrypted is True


def test_freeze_asset_classification_maps_to_risk_rating():
    draft = SystemModelDraft(
        assets=[
            ModelAsset(
                id="asset1",
                name="Card Number",
                classification="pci",
                owner_id=None,
                source="prose",
                source_spans=(_span(),),
            )
        ]
    )
    model = freeze_draft(draft, model_id="proj1")
    asset = model.assets[0]
    assert asset.classification == "pci"
    assert asset.confidentiality > 1
    assert asset.integrity > 1


def test_freeze_unknown_classification_defaults_to_low_risk():
    draft = SystemModelDraft(
        assets=[
            ModelAsset(
                id="asset1",
                name="Something",
                classification="unclassified",
                owner_id=None,
                source="prose",
                source_spans=(_span(),),
            )
        ]
    )
    model = freeze_draft(draft, model_id="proj1")
    asset = model.assets[0]
    assert (asset.confidentiality, asset.integrity, asset.availability) == (1, 1, 1)


def test_freeze_is_deterministic_for_identical_input():
    draft = SystemModelDraft(
        components=[
            ModelComponent(
                id="c1",
                name="Auth Service",
                kind="process",
                trust_zone_id=None,
                technology_tags=("OAuth2",),
                source="mermaid",
                source_spans=(_span(),),
            )
        ]
    )
    model1 = freeze_draft(draft, model_id="proj1")
    model2 = freeze_draft(draft, model_id="proj1")
    assert model1 == model2


def test_freeze_carries_over_declared_controls():
    draft = SystemModelDraft(
        components=[
            ModelComponent(
                id="c1",
                name="Auth Service",
                kind="process",
                trust_zone_id=None,
                technology_tags=(),
                source="mermaid",
                source_spans=(_span(),),
            )
        ],
        declared_controls=[
            DeclaredControl(
                id="control-mfa",
                name="MFA",
                applies_to_ids=("c1",),
                source="prose",
                source_spans=(_span(),),
            )
        ],
    )
    model = freeze_draft(draft, model_id="proj1")
    assert len(model.declared_controls) == 1
    control = model.declared_controls[0]
    assert control.name == "MFA"
    assert control.applies_to_ids == ("c1",)
    assert control.provenance == "agent_generated"
