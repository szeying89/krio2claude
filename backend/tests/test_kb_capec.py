from app.services.kb.capec import parse_capec_bundle
from tests.kb_fixtures import load_json


def test_maps_capec_ids_to_attack_technique_ids():
    bundle = load_json("capec_bundle.json")
    mapping = parse_capec_bundle(bundle)

    assert mapping["T1190"] == ["CAPEC-66"]
    assert mapping["T1071"] == ["CAPEC-94"]


def test_pattern_without_attack_mapping_contributes_nothing():
    bundle = load_json("capec_bundle.json")
    mapping = parse_capec_bundle(bundle)

    for capec_ids in mapping.values():
        assert "CAPEC-1" not in capec_ids


def test_mapping_to_a_technique_not_in_the_kb_is_still_returned():
    """The parser itself doesn't know what's "in the KB" — that check and
    the resulting unresolved-mapping bookkeeping happens in
    merge_relationships (tested in test_kb_snapshot.py). Here we just
    confirm the raw mapping is passed through faithfully."""
    bundle = load_json("capec_bundle.json")
    mapping = parse_capec_bundle(bundle)

    assert mapping["T9999-unknown"] == ["CAPEC-94"]
