import json

import pytest

from app.api.deps import get_llm_gateway
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
to the payment processor over HTTPS.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway --> Processor[(Payment Processor)]
```

We store the card token, though no classification is documented here.
"""

EMPTY_EXTRACTION = json.dumps(
    {
        "components": [],
        "actors": [],
        "flows": [],
        "assets": [],
        "trust_zones": [],
        "declared_controls": [],
    }
)


def _override_fake_gateway(tmp_path, respond=None):
    def _dep():
        provider = FakeProvider(respond=respond or (lambda _p: EMPTY_EXTRACTION))
        return LLMGateway(provider, cache_dir=tmp_path / "llm-cache")

    return _dep


@pytest.mark.asyncio
async def test_model_draft_without_configured_provider_returns_503(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    draft_resp = await client.post(f"/projects/{project_id}/model-draft")
    assert draft_resp.status_code == 503
    assert "no LLM provider configured" in draft_resp.json()["detail"]


@pytest.mark.asyncio
async def test_model_draft_missing_project_404(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects/does-not-exist/model-draft")
        assert resp.status_code == 404
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_model_draft_merges_mermaid_and_prose_end_to_end(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )

        draft_resp = await client.post(f"/projects/{project_id}/model-draft")
        assert draft_resp.status_code == 200
        body = draft_resp.json()

        names = {c["name"] for c in body["components"]} | {a["name"] for a in body["actors"]}
        assert {"Client", "Gateway", "Payment Processor"} <= names
        assert len(body["flows"]) == 2
        assert body["needs_input"] is False
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_model_draft_surfaces_completeness_findings(client, tmp_path):
    from app.main import app

    prose_with_unclassified_asset = json.dumps(
        {
            "components": [],
            "actors": [],
            "flows": [],
            "assets": [
                {
                    "name": "Card Token",
                    "confidence": 0.8,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "trust_zones": [],
            "declared_controls": [],
        }
    )
    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(
        tmp_path, respond=lambda _p: prose_with_unclassified_asset
    )
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )

        draft_resp = await client.post(f"/projects/{project_id}/model-draft")
        body = draft_resp.json()
        assert body["needs_input"] is True
        assert any(f["kind"] == "unclassified_asset" for f in body["completeness_findings"])
        assert any(a["kind"] in ("inference", "default") for a in body["assumptions"])
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
