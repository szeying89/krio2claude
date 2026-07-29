from datetime import UTC, datetime

from app.services.systemmodel.models import (
    Asset,
    Component,
    Dataflow,
    OutOfScopeDeclaration,
    SystemModel,
    TrustZone,
)
from app.services.systemmodel.otm import OTM_VERSION, from_otm, to_otm


def _full_model() -> SystemModel:
    return SystemModel(
        id="proj1",
        version=2,
        parent_version=1,
        trust_zones=[
            TrustZone(id="tz1", name="Internal", trust_rating=3, description="core services", provenance="user_asserted")
        ],
        components=[
            Component(
                id="c1",
                name="Auth Service",
                kind="process",
                trust_zone_id="tz1",
                technology_tags=("OAuth2", "JWT"),
                description="handles login",
                provenance="agent_generated",
                out_of_scope=False,
            ),
            Component(
                id="c2",
                name="SCADA Historian",
                kind="datastore",
                trust_zone_id="tz1",
                provenance="agent_generated",
                out_of_scope=True,
                out_of_scope_reason="OT/ICS indicator detected: 'scada'",
            ),
        ],
        dataflows=[
            Dataflow(
                id="f1",
                name="login",
                source_id="c1",
                destination_id="c2",
                bidirectional=False,
                protocol="HTTPS",
                authenticated=True,
                encrypted=True,
                provenance="agent_generated",
            )
        ],
        assets=[
            Asset(
                id="asset1",
                name="Session Token",
                classification="pii",
                confidentiality=8,
                integrity=5,
                availability=5,
                owner_id="c1",
                provenance="agent_generated",
            )
        ],
        out_of_scope=[
            OutOfScopeDeclaration(
                id="oos-c2", subject_id="c2", category="ot_ics", indicator="scada", reason="..."
            )
        ],
        change_summary=["initial version"],
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_to_otm_sets_otm_version_field():
    otm = to_otm(_full_model())
    assert otm["otmVersion"] == OTM_VERSION


def test_to_otm_component_parent_references_trust_zone():
    otm = to_otm(_full_model())
    component = next(c for c in otm["components"] if c["id"] == "c1")
    assert component["parent"] == {"trustZone": "tz1"}
    assert component["type"] == "process"


def test_to_otm_asset_has_numeric_risk_ratings():
    otm = to_otm(_full_model())
    asset = otm["assets"][0]
    assert asset["risk"] == {"confidentiality": 8, "integrity": 5, "availability": 5}


def test_round_trip_reproduces_model_exactly():
    model = _full_model()
    assert from_otm(to_otm(model)) == model


def test_round_trip_with_no_out_of_scope_or_optional_fields():
    model = SystemModel(id="proj2", version=1, parent_version=None)
    assert from_otm(to_otm(model)) == model


def test_round_trip_preserves_provenance():
    model = _full_model()
    restored = from_otm(to_otm(model))
    assert restored.trust_zones[0].provenance == "user_asserted"
    assert restored.components[0].provenance == "agent_generated"


def test_round_trip_preserves_out_of_scope_flag_and_reason():
    model = _full_model()
    restored = from_otm(to_otm(model))
    flagged = next(c for c in restored.components if c.id == "c2")
    assert flagged.out_of_scope is True
    assert flagged.out_of_scope_reason == "OT/ICS indicator detected: 'scada'"
    assert len(restored.out_of_scope) == 1
    assert restored.out_of_scope[0].category == "ot_ics"


def test_otm_document_is_json_serializable():
    import json

    otm = to_otm(_full_model())
    # must not raise
    json.dumps(otm)
