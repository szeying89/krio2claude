from app.services.kb.d3fend import parse_d3fend_mappings
from tests.kb_fixtures import load_json


def test_maps_attack_ids_to_d3fend_ids():
    rows = load_json("d3fend_mappings.json")
    mapping = parse_d3fend_mappings(rows)

    assert mapping["T1190"] == ["D3-AI", "D3-NM"]
    assert mapping["T1071"] == ["D3-NTA"]


def test_row_missing_either_id_is_ignored():
    rows = [
        {"attack_id": "T1190"},  # missing d3fend_id
        {"d3fend_id": "D3-NM"},  # missing attack_id
        {"attack_id": "T1071", "d3fend_id": "D3-NTA"},
    ]
    mapping = parse_d3fend_mappings(rows)
    assert mapping == {"T1071": ["D3-NTA"]}
