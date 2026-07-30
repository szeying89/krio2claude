from app.services.kb.atlas import parse_atlas_data
from tests.kb_fixtures import load_yaml


def test_parses_atlas_techniques_only():
    data = load_yaml("atlas_data.yaml")
    chunks = parse_atlas_data(data)

    ids = {c.id for c in chunks}
    assert ids == {"AML.T0000", "AML.T0000.000", "AML.T0043"}, "mitigation entry excluded"


def test_resolves_tactic_ids_to_names():
    data = load_yaml("atlas_data.yaml")
    chunks = {c.id: c for c in parse_atlas_data(data)}

    assert chunks["AML.T0000"].tactics == ("Reconnaissance",)
    assert chunks["AML.T0043"].tactics == ("Initial Access",)


def test_subtechnique_without_own_tactics_is_empty_not_error():
    data = load_yaml("atlas_data.yaml")
    chunks = {c.id: c for c in parse_atlas_data(data)}

    assert chunks["AML.T0000.000"].tactics == ()


def test_atlas_chunks_have_no_att_ck_only_fields():
    data = load_yaml("atlas_data.yaml")
    chunks = parse_atlas_data(data)

    for chunk in chunks:
        assert chunk.matrix == "atlas"
        assert chunk.platforms == ()
        assert chunk.data_sources == ()
        assert chunk.detection == ""
