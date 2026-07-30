from app.services.enumeration.engine import enumerate_threats
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


def _categories_for(candidates, element_id, framework="stride"):
    return {c.category for c in candidates if c.element_id == element_id and c.framework == framework}


def test_external_entity_gets_exactly_spoofing_and_repudiation():
    model = _model(components=[Component(id="a1", name="User", kind="external_entity", trust_zone_id="tz1")])
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "a1") == {"spoofing", "repudiation"}


def test_process_gets_all_six_stride_categories():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "c1") == {
        "spoofing",
        "tampering",
        "repudiation",
        "information_disclosure",
        "denial_of_service",
        "elevation_of_privilege",
    }


def test_plain_datastore_gets_exactly_three_categories():
    model = _model(components=[Component(id="d1", name="DB", kind="datastore", trust_zone_id="tz1")])
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "d1") == {"tampering", "information_disclosure", "denial_of_service"}


def test_log_tagged_datastore_additionally_gets_repudiation():
    model = _model(
        components=[
            Component(id="d1", name="Audit Log", kind="datastore", trust_zone_id="tz1", technology_tags=("log",))
        ]
    )
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "d1") == {
        "tampering",
        "information_disclosure",
        "denial_of_service",
        "repudiation",
    }


def test_dataflow_gets_exactly_three_categories():
    model = _model(
        components=[
            Component(id="c1", name="A", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="B", kind="process", trust_zone_id="tz1"),
        ],
        dataflows=[Dataflow(id="f1", name="call", source_id="c1", destination_id="c2")],
    )
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "f1") == {"tampering", "information_disclosure", "denial_of_service"}


def test_linddun_fires_on_component_owning_pii_asset():
    model = _model(
        components=[Component(id="d1", name="User DB", kind="datastore", trust_zone_id="tz1")],
        assets=[
            Asset(id="a1", name="SSN", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="d1")
        ],
    )
    candidates = enumerate_threats(model, RULESET)
    linddun = _categories_for(candidates, "d1", framework="linddun")
    assert linddun == {
        "linkability",
        "identifiability",
        "non_repudiation",
        "detectability",
        "disclosure_of_information",
        "unawareness",
        "non_compliance",
    }


def test_linddun_fires_on_component_with_direct_pii_tag():
    model = _model(
        components=[
            Component(id="c1", name="Analytics", kind="process", trust_zone_id="tz1", technology_tags=("pii",))
        ]
    )
    candidates = enumerate_threats(model, RULESET)
    assert len(_categories_for(candidates, "c1", framework="linddun")) == 7


def test_linddun_does_not_fire_on_non_personal_data_elements():
    model = _model(
        components=[
            Component(id="c1", name="Public Info Service", kind="process", trust_zone_id="tz1"),
        ],
        assets=[
            Asset(id="a1", name="Marketing copy", classification="unclassified", confidentiality=1, integrity=1, availability=1, owner_id="c1")
        ],
    )
    candidates = enumerate_threats(model, RULESET)
    assert _categories_for(candidates, "c1", framework="linddun") == set()


def test_linddun_propagates_to_dataflow_touching_personal_data_component():
    model = _model(
        components=[
            Component(id="c1", name="App", kind="process", trust_zone_id="tz1"),
            Component(id="d1", name="User DB", kind="datastore", trust_zone_id="tz1"),
        ],
        dataflows=[Dataflow(id="f1", name="query", source_id="c1", destination_id="d1")],
        assets=[
            Asset(id="a1", name="SSN", classification="pii", confidentiality=8, integrity=5, availability=5, owner_id="d1")
        ],
    )
    candidates = enumerate_threats(model, RULESET)
    assert len(_categories_for(candidates, "f1", framework="linddun")) == 7


def test_out_of_scope_component_generates_zero_threats():
    model = _model(
        components=[
            Component(id="c1", name="SCADA Historian", kind="datastore", trust_zone_id="tz1", out_of_scope=True)
        ]
    )
    candidates = enumerate_threats(model, RULESET)
    assert [c for c in candidates if c.element_id == "c1"] == []


def test_dataflow_between_two_out_of_scope_components_generates_zero_threats():
    model = _model(
        components=[
            Component(id="c1", name="PLC", kind="process", trust_zone_id="tz1", out_of_scope=True),
            Component(id="c2", name="RTU", kind="process", trust_zone_id="tz1", out_of_scope=True),
        ],
        dataflows=[Dataflow(id="f1", name="control", source_id="c1", destination_id="c2")],
    )
    candidates = enumerate_threats(model, RULESET)
    assert [c for c in candidates if c.element_id == "f1"] == []


def test_dataflow_with_one_out_of_scope_endpoint_is_still_enumerated():
    model = _model(
        components=[
            Component(id="c1", name="Gateway", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="SCADA Historian", kind="datastore", trust_zone_id="tz1", out_of_scope=True),
        ],
        dataflows=[Dataflow(id="f1", name="forward", source_id="c1", destination_id="c2")],
    )
    candidates = enumerate_threats(model, RULESET)
    assert len(_categories_for(candidates, "f1")) == 3


def test_candidate_ids_are_stable_across_runs():
    model = _model(components=[Component(id="c1", name="Svc", kind="process", trust_zone_id="tz1")])
    first = enumerate_threats(model, RULESET)
    second = enumerate_threats(model, RULESET)
    assert [c.id for c in first] == [c.id for c in second]


def test_candidate_id_derived_from_element_category_and_ruleset_version():
    model = _model(components=[Component(id="c1", name="Svc", kind="external_entity", trust_zone_id="tz1")])
    candidates = enumerate_threats(model, RULESET)
    spoofing = next(c for c in candidates if c.category == "spoofing")
    assert spoofing.id == f"c1::spoofing::{RULESET.version}"
