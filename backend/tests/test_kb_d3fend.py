import pytest

from app.services.kb.d3fend import D3fendParseError, parse_d3fend_csv
from tests.kb_fixtures import load_text


def _read_fixture() -> str:
    return load_text("d3fend_catalog.csv")


def test_parses_all_rows():
    techniques = parse_d3fend_csv(_read_fixture())
    ids = {t.id for t in techniques}
    assert "D3-OAM" in ids
    assert "D3-DPLM" in ids
    assert len(techniques) == 15


def test_depth_assigned_from_populated_column():
    techniques = {t.id: t for t in parse_d3fend_csv(_read_fixture())}

    assert techniques["D3-OAM"].depth == 0
    assert techniques["D3-OAM"].name == "Operational Activity Mapping"
    assert techniques["D3-OM"].depth == 1
    assert techniques["D3-OM"].name == "Organization Mapping"
    assert techniques["D3-DPLM"].depth == 2
    assert techniques["D3-DPLM"].name == "Direct Physical Link Mapping"


def test_parent_linkage_follows_hierarchy():
    techniques = {t.id: t for t in parse_d3fend_csv(_read_fixture())}

    assert techniques["D3-OAM"].parent_id is None
    assert techniques["D3-OM"].parent_id == "D3-OAM"
    assert techniques["D3-PLM"].parent_id == "D3-NM"
    assert techniques["D3-DPLM"].parent_id == "D3-PLM"
    assert techniques["D3-APLM"].parent_id == "D3-PLM"
    # D3-NVA follows the D3-PLM/D3-DPLM/D3-APLM branch but is itself a
    # sibling Level-0 entry under D3-NM, not a child of D3-PLM.
    assert techniques["D3-NVA"].parent_id == "D3-NM"


def test_tactic_is_read_per_row():
    techniques = {t.id: t for t in parse_d3fend_csv(_read_fixture())}
    assert techniques["D3-OAM"].tactic == "Model"
    assert techniques["D3-SCH"].tactic == "Harden"
    assert techniques["D3-NTA"].tactic == "Detect"
    assert techniques["D3-AMED"].tactic == "Isolate"


def test_definition_with_embedded_comma_parses_correctly():
    techniques = {t.id: t for t in parse_d3fend_csv(_read_fixture())}
    assert "people, roles, and groups" in techniques["D3-OM"].definition


def test_rejects_unexpected_header():
    bad_csv = "Foo,Bar\n1,2\n"
    with pytest.raises(D3fendParseError, match="unexpected D3FEND CSV header"):
        parse_d3fend_csv(bad_csv)
