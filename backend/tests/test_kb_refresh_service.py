import pytest

from app.services.kb.models import UnsupportedDomainError
from app.services.kb.refresh_service import KBRefreshService
from app.services.kb.snapshot import read_manifest
from tests.kb_fixtures import load_json, load_text, load_yaml


def _fixture_fetchers():
    return {
        "fetch_attack_enterprise": lambda: (
            load_json("enterprise_bundle.json"),
            "19.1",
            "https://example/enterprise-attack-19.1.json",
        ),
        "fetch_atlas": lambda: (
            load_yaml("atlas_data.yaml"),
            "5.6.0",
            "https://example/ATLAS.yaml",
        ),
        "fetch_capec": lambda: (
            load_json("capec_bundle.json"),
            "3.9",
            "https://example/stix-capec.json",
        ),
        "fetch_d3fend": lambda: (
            load_text("d3fend_catalog.csv"),
            "unknown",
            "https://example/D3FEND.csv",
        ),
    }


def test_refresh_writes_a_snapshot_with_expected_manifest(tmp_path):
    service = KBRefreshService(tmp_path, **_fixture_fetchers())

    snapshot_dir = service.refresh()

    manifest = read_manifest(snapshot_dir)
    assert manifest["chunk_counts"] == {"enterprise": 3, "atlas": 3}
    assert manifest["versions"] == {
        "attack_enterprise": "19.1",
        "atlas": "5.6.0",
        "capec": "3.9",
        "d3fend": "unknown",
    }
    assert manifest["unresolved_capec_mappings"] == ["CAPEC-94"]
    assert manifest["d3fend_catalog_size"] == 15
    assert manifest["d3fend_inferred_mapping_count"] >= 0


def test_rerunning_refresh_against_unchanged_fixtures_is_a_noop(tmp_path):
    service = KBRefreshService(tmp_path, **_fixture_fetchers())

    first = service.refresh()
    second = service.refresh()

    assert first == second
    assert len(list(tmp_path.iterdir())) == 1


def test_partial_failure_publishes_nothing(tmp_path):
    fetchers = _fixture_fetchers()

    def failing_d3fend_fetch():
        raise RuntimeError("network error fetching D3FEND")

    fetchers["fetch_d3fend"] = failing_d3fend_fetch
    service = KBRefreshService(tmp_path, **fetchers)

    with pytest.raises(RuntimeError, match="network error"):
        service.refresh()

    assert list(tmp_path.iterdir()) == [], "a failed refresh must not publish a partial snapshot"


def test_ics_tainted_enterprise_fetch_rejected_and_publishes_nothing(tmp_path):
    fetchers = _fixture_fetchers()
    fetchers["fetch_attack_enterprise"] = lambda: (
        load_json("enterprise_bundle_with_ics.json"),
        "19.1",
        "https://example/enterprise-attack-19.1.json",
    )
    service = KBRefreshService(tmp_path, **fetchers)

    with pytest.raises(UnsupportedDomainError):
        service.refresh()

    assert list(tmp_path.iterdir()) == []
