import json

import pytest

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.core.config import get_settings
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import write_snapshot as write_kb_snapshot
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
}

DESIGN_DOC = """\
# Payments Platform

The gateway receives requests from the public internet and forwards them
to the payment processor over HTTPS. An isolated batch job also runs
internally with no inbound connection from the internet.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway --> Processor[(Payment Processor)]
```
"""

_TECHNIQUE = TechniqueChunk(
    id="T1499",
    matrix="enterprise",
    name="Endpoint Denial of Service",
    tactics=("impact",),
    description="Adversaries may flood a target host to exhaust resources and deny service, "
    "tampering with availability via denial of service.",
    detection="",
    platforms=(),
    data_sources=(),
    relationships={"capec": ("CAPEC-125",)},
)


def _write_kb_snapshot(kb_dir):
    return write_kb_snapshot(
        kb_dir, [_TECHNIQUE],
        versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-01-01T00:00:00Z",
    )


def _extraction_with_isolated_component() -> str:
    return json.dumps(
        {
            "components": [
                {
                    "name": "Isolated Batch Job",
                    "kind": "process",
                    "technology_tags": [],
                    "confidence": 0.9,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "actors": [],
            "flows": [],
            "assets": [
                {
                    "name": "Card Token",
                    "classification": "confidential",
                    "owner_name": "Payment Processor",
                    "confidence": 0.9,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "trust_zones": [],
            "declared_controls": [],
        }
    )


def _gateway_dep(tmp_path, response: str):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


NORMAL_INTEL_RESPONSE = json.dumps(
    {
        "technique_ids": ["T1499"],
        "cves": [],
        "affected_products": [{"vendor": "acme", "product": "gateway"}],
        "actor": "APT1",
        "targeted_sectors": [],
        "campaign_start": None,
        "campaign_end": None,
        "ttp_summary": "Denial of service reported against the gateway.",
        "source_credibility": "medium",
    }
)


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


async def _freeze_project(client, tmp_path, app):
    _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, _extraction_with_isolated_component())
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    return project_id


async def _ingest_article(client, tmp_path, app, response: str, text: str) -> str:
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, response)
    try:
        resp = await client.post("/intel/articles", json={"text": text})
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    return resp.json()["content_hash"]


@pytest.mark.asyncio
async def test_revision_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.post(f"/projects/{project_id}/revisions", json={})
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_revision_for_unknown_project_is_404(client):
    result = await client.post("/projects/does-not-exist/revisions", json={})
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_create_initial_revision_baseline(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    resp = await client.post(f"/projects/{project_id}/revisions", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert body["parent_revision_id"] is None
    assert body["paths"]
    assert body["currency"]["intel_article_count"] == 0


@pytest.mark.asyncio
async def test_revision_with_unknown_intel_hash_is_404(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    resp = await client.post(
        f"/projects/{project_id}/revisions", json={"intel_article_content_hashes": ["0" * 64]}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_and_list_revisions(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    created = await client.post(f"/projects/{project_id}/revisions", json={})
    revision_id = created.json()["id"]

    fetched = await client.get(f"/projects/{project_id}/revisions/{revision_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == revision_id

    listed = await client.get(f"/projects/{project_id}/revisions")
    assert listed.status_code == 200
    assert [r["id"] for r in listed.json()] == [revision_id]


@pytest.mark.asyncio
async def test_diff_on_initial_revision_is_409(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    created = await client.post(f"/projects/{project_id}/revisions", json={})
    revision_id = created.json()["id"]

    resp = await client.get(f"/projects/{project_id}/revisions/{revision_id}/diff")
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_revision_diff_for_missing_revision_is_404(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    resp = await client.get(f"/projects/{project_id}/revisions/does-not-exist/diff")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_corroborating_intel_revision_raises_path_likelihood_and_shows_in_diff(
    client, tmp_path
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    baseline = await client.post(f"/projects/{project_id}/revisions", json={})
    baseline_paths = {p["id"]: p["aggregate_likelihood"] for p in baseline.json()["paths"]}
    assert baseline_paths

    content_hash = await _ingest_article(
        client, tmp_path, app, NORMAL_INTEL_RESPONSE, "APT1 launched a DoS attack on the gateway using T1499."
    )

    revised = await client.post(
        f"/projects/{project_id}/revisions", json={"intel_article_content_hashes": [content_hash]}
    )
    assert revised.status_code == 200
    revised_body = revised.json()
    assert revised_body["parent_revision_id"] == baseline.json()["id"]
    assert revised_body["intel_article_hashes"] == [content_hash]
    assert revised_body["currency"]["intel_article_count"] == 1

    revised_paths = {p["id"]: p["aggregate_likelihood"] for p in revised_body["paths"]}
    for path_id, baseline_likelihood in baseline_paths.items():
        assert revised_paths[path_id] > baseline_likelihood

    diff = await client.get(f"/projects/{project_id}/revisions/{revised_body['id']}/diff")
    assert diff.status_code == 200
    diff_body = diff.json()
    assert len(diff_body["changed_paths"]) == len(baseline_paths)
    assert diff_body["risk_score_delta"] > 0
