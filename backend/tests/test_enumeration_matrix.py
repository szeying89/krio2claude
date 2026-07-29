from app.services.enumeration.matrix import build_enumeration_result
from app.services.enumeration.ruleset import load_ruleset
from app.services.systemmodel.models import Asset, Component, Dataflow, SystemModel, TrustZone

RULESET = load_ruleset()


def _model(**kwargs) -> SystemModel:
    defaults = {
        "id": "p1",
        "version": 1,
        "parent_version": None,
        "trust_zones": [TrustZone(id="tz1", name="Internal", trust_rating=1)],
    }
    defaults.update(kwargs)
    return SystemModel(**defaults)


def test_matrix_includes_every_component_and_dataflow():
    model = _model(
        components=[
            Component(id="c1", name="A", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="B", kind="datastore", trust_zone_id="tz1", out_of_scope=True),
        ],
        dataflows=[Dataflow(id="f1", name="call", source_id="c1", destination_id="c2")],
    )
    result = build_enumeration_result(model, RULESET)
    ids = {row.element_id for row in result.matrix}
    assert ids == {"c1", "c2", "f1"}


def test_out_of_scope_row_has_empty_categories():
    model = _model(
        components=[Component(id="c1", name="SCADA Historian", kind="datastore", trust_zone_id="tz1", out_of_scope=True)]
    )
    result = build_enumeration_result(model, RULESET)
    row = next(r for r in result.matrix if r.element_id == "c1")
    assert row.stride_categories == ()
    assert row.linddun_categories == ()


def test_linddun_present_true_when_personal_data_exists():
    model = _model(
        components=[Component(id="c1", name="User DB", kind="datastore", trust_zone_id="tz1")],
        assets=[Asset(id="a1", name="SSN", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="c1")],
    )
    result = build_enumeration_result(model, RULESET)
    assert result.linddun_present is True


def test_linddun_present_false_without_personal_data():
    model = _model(components=[Component(id="c1", name="Public Service", kind="process", trust_zone_id="tz1")])
    result = build_enumeration_result(model, RULESET)
    assert result.linddun_present is False


def test_matrix_row_carries_element_name_and_kind():
    model = _model(components=[Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    result = build_enumeration_result(model, RULESET)
    row = next(r for r in result.matrix if r.element_id == "c1")
    assert row.element_name == "Auth Service"
    assert row.element_kind == "process"


def test_ruleset_version_on_result():
    result = build_enumeration_result(_model(), RULESET)
    assert result.ruleset_version == RULESET.version
