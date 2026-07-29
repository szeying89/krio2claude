import pytest

from app.api import retrieval as retrieval_module
from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.snapshot import write_snapshot as write_kb_snapshot
from tests.kb_fixtures import load_json


@pytest.fixture(autouse=True)
def _clear_retrieval_caches():
    retrieval_module._technique_collections.clear()
    retrieval_module._statement_collections.clear()
    yield
    retrieval_module._technique_collections.clear()
    retrieval_module._statement_collections.clear()


def _write_kb_snapshot(tmp_path):
    chunks = parse_attack_enterprise_bundle(load_json("enterprise_bundle.json"))
    return write_kb_snapshot(
        tmp_path,
        chunks,
        versions={"attack_enterprise": "19.1"},
        source_urls={},
        fetched_at="2026-01-01T00:00:00Z",
    )


@pytest.mark.asyncio
async def test_search_techniques_returns_ranked_results(client, monkeypatch, tmp_path):
    from app.core.config import get_settings

    kb_dir = get_settings().kb_dir
    snapshot_dir = _write_kb_snapshot(kb_dir)

    resp = await client.get(
        f"/kb/snapshots/{snapshot_dir.name}/retrieval", params={"q": "exploit public facing"}
    )
    assert resp.status_code == 200
    results = resp.json()
    assert results
    assert results[0]["doc_id"] == "T1190"
    assert "bm25_rank" in results[0]
    assert "dense_rank" in results[0]


@pytest.mark.asyncio
async def test_search_techniques_matrix_filter(client):
    from app.core.config import get_settings

    kb_dir = get_settings().kb_dir
    snapshot_dir = _write_kb_snapshot(kb_dir)

    resp = await client.get(
        f"/kb/snapshots/{snapshot_dir.name}/retrieval",
        params={"q": "exploit application protocol", "matrix": "atlas"},
    )
    assert resp.status_code == 200
    assert resp.json() == []  # fixture bundle has no atlas techniques


@pytest.mark.asyncio
async def test_search_techniques_missing_snapshot_404(client):
    resp = await client.get("/kb/snapshots/does-not-exist/retrieval", params={"q": "anything"})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_search_statements_missing_snapshot_404(client):
    resp = await client.get("/cri/snapshots/does-not-exist/retrieval", params={"q": "anything"})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_cri_snapshot_manifest_by_hash(client):
    from app.core.config import get_settings
    from app.services.cri.ingestion_service import CRIIngestionService

    cri_dir = get_settings().cri_dir
    service = CRIIngestionService(cri_dir)
    snapshot_dir = service.ingest(
        "tests/fixtures/cri/sample_cri_profile.xlsx", "sample.xlsx", "2026-01-01T00:00:00Z"
    )

    resp = await client.get(f"/cri/snapshots/{snapshot_dir.name}")
    assert resp.status_code == 200
    assert resp.json()["statement_count"] == 3


@pytest.mark.asyncio
async def test_search_statements_returns_ranked_results(client):
    from app.core.config import get_settings
    from app.services.cri.ingestion_service import CRIIngestionService

    cri_dir = get_settings().cri_dir
    service = CRIIngestionService(cri_dir)
    snapshot_dir = service.ingest(
        "tests/fixtures/cri/sample_cri_profile.xlsx", "sample.xlsx", "2026-01-01T00:00:00Z"
    )

    resp = await client.get(
        f"/cri/snapshots/{snapshot_dir.name}/retrieval",
        params={"q": "governance alignment mission"},
    )
    assert resp.status_code == 200
    results = resp.json()
    assert results
    assert results[0]["doc_id"] == "GV.OC-01.01"
