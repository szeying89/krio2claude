import pytest

from app.api.deps import get_kb_refresh_service
from app.core.config import get_settings
from app.services.kb.refresh_service import KBRefreshService
from tests.kb_fixtures import load_json, load_text, load_yaml


def _install_fixture_kb_service():
    """Point the overridden KBRefreshService at the *same* kb_dir the
    read-only list/get endpoints resolve via get_settings().kb_dir (the temp
    per-test data dir from the `app_env` fixture) — otherwise refresh() would
    publish to one directory while list/get read from another."""
    from app.main import app

    kb_dir = get_settings().kb_dir

    def override() -> KBRefreshService:
        return KBRefreshService(
            kb_dir,
            fetch_attack_enterprise=lambda: (
                load_json("enterprise_bundle.json"),
                "19.1",
                "https://example/enterprise-attack-19.1.json",
            ),
            fetch_atlas=lambda: (
                load_yaml("atlas_data.yaml"),
                "5.6.0",
                "https://example/ATLAS.yaml",
            ),
            fetch_capec=lambda: (
                load_json("capec_bundle.json"),
                "3.9",
                "https://example/stix-capec.json",
            ),
            fetch_d3fend=lambda: (
                load_text("d3fend_catalog.csv"),
                "unknown",
                "https://example/D3FEND.csv",
            ),
        )

    app.dependency_overrides[get_kb_refresh_service] = override
    return app


@pytest.mark.asyncio
async def test_refresh_then_list_then_get_snapshot(client):
    app = _install_fixture_kb_service()
    try:
        refreshed = await client.post("/kb/refresh")
        assert refreshed.status_code == 200
        manifest = refreshed.json()
        assert manifest["chunk_counts"] == {"enterprise": 3, "atlas": 3}
        content_hash = manifest["content_hash"]

        listed = await client.get("/kb/snapshots")
        assert listed.status_code == 200
        assert any(m["content_hash"] == content_hash for m in listed.json())

        fetched = await client.get(f"/kb/snapshots/{content_hash}")
        assert fetched.status_code == 200
        assert fetched.json()["content_hash"] == content_hash

        missing = await client.get("/kb/snapshots/does-not-exist")
        assert missing.status_code == 404
    finally:
        app.dependency_overrides.pop(get_kb_refresh_service, None)


@pytest.mark.asyncio
async def test_rerunning_refresh_is_a_noop_via_api(client):
    app = _install_fixture_kb_service()
    try:
        first = await client.post("/kb/refresh")
        second = await client.post("/kb/refresh")
        assert first.json()["content_hash"] == second.json()["content_hash"]

        listed = await client.get("/kb/snapshots")
        assert len(listed.json()) == 1
    finally:
        app.dependency_overrides.pop(get_kb_refresh_service, None)


@pytest.mark.asyncio
async def test_list_snapshots_empty_when_no_kb_dir(client):
    resp = await client.get("/kb/snapshots")
    assert resp.status_code == 200
    assert resp.json() == []
