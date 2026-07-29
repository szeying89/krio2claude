import pytest

from app.services.systemmodel.edits import (
    AssetEdit,
    ComponentEdit,
    DataflowEdit,
    ModelEdits,
    TrustZoneEdit,
    UnknownElementError,
    apply_edits,
)
from app.services.systemmodel.models import (
    Asset,
    Component,
    Dataflow,
    SystemModel,
    TrustZone,
)


def _model() -> SystemModel:
    return SystemModel(
        id="proj1",
        version=1,
        parent_version=None,
        trust_zones=[TrustZone(id="tz1", name="Internal", trust_rating=1)],
        components=[
            Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")
        ],
        dataflows=[Dataflow(id="f1", name="login", source_id="c1", destination_id="c1")],
        assets=[Asset(id="a1", name="Token", classification="unclassified", confidentiality=1, integrity=1, availability=1)],
    )


def test_apply_edits_does_not_mutate_the_original_model():
    original = _model()
    apply_edits(original, ModelEdits(components=[ComponentEdit(id="c1", kind="datastore")]))
    assert original.components[0].kind == "process"


def test_component_edit_updates_kind_and_marks_user_asserted():
    updated = apply_edits(_model(), ModelEdits(components=[ComponentEdit(id="c1", kind="datastore")]))
    component = updated.components[0]
    assert component.kind == "datastore"
    assert component.provenance == "user_asserted"


def test_component_edit_only_touches_provided_fields():
    updated = apply_edits(_model(), ModelEdits(components=[ComponentEdit(id="c1", kind="datastore")]))
    component = updated.components[0]
    assert component.name == "Auth Service"  # unchanged


def test_unknown_component_id_raises():
    with pytest.raises(UnknownElementError):
        apply_edits(_model(), ModelEdits(components=[ComponentEdit(id="does-not-exist", kind="datastore")]))


def test_dataflow_edit_sets_protocol_and_provenance():
    updated = apply_edits(
        _model(), ModelEdits(dataflows=[DataflowEdit(id="f1", protocol="HTTPS", authenticated=True)])
    )
    flow = updated.dataflows[0]
    assert flow.protocol == "HTTPS"
    assert flow.authenticated is True
    assert flow.provenance == "user_asserted"


def test_asset_edit_sets_classification():
    updated = apply_edits(_model(), ModelEdits(assets=[AssetEdit(id="a1", classification="pci")]))
    asset = updated.assets[0]
    assert asset.classification == "pci"
    assert asset.provenance == "user_asserted"


def test_trust_zone_edit_sets_trust_rating():
    updated = apply_edits(_model(), ModelEdits(trust_zones=[TrustZoneEdit(id="tz1", trust_rating=5)]))
    zone = updated.trust_zones[0]
    assert zone.trust_rating == 5
    assert zone.provenance == "user_asserted"


def test_unedited_elements_keep_agent_generated_provenance():
    model = _model()
    model.components.append(
        Component(id="c2", name="Other", kind="process", trust_zone_id="tz1")
    )
    updated = apply_edits(model, ModelEdits(components=[ComponentEdit(id="c1", kind="datastore")]))
    untouched = next(c for c in updated.components if c.id == "c2")
    assert untouched.provenance == "agent_generated"


def test_is_empty():
    assert ModelEdits().is_empty() is True
    assert ModelEdits(components=[ComponentEdit(id="c1")]).is_empty() is False
