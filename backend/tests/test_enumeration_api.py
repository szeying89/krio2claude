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
    Gateway --> Historian[SCADA Historian]
```

We store the card token here.
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
async def test_threats_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.get(f"/projects/{project_id}/system-model/threats")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_threats_endpoint_returns_matrix_and_excludes_out_of_scope_threats(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        threats_resp = await client.get(f"/projects/{project_id}/system-model/threats")
        assert threats_resp.status_code == 200
        body = threats_resp.json()
        assert body["ruleset_version"] == "1.0.0"
        assert body["linddun_present"] is False

        historian_row = next(r for r in body["matrix"] if "Historian" in r["element_name"])
        assert historian_row["stride_categories"] == []

        gateway_row = next(r for r in body["matrix"] if r["element_name"] == "Gateway")
        assert set(gateway_row["stride_categories"]) == {
            "spoofing",
            "tampering",
            "repudiation",
            "information_disclosure",
            "denial_of_service",
            "elevation_of_privilege",
        }
        assert all(c["element_id"] != historian_row["element_id"] for c in body["candidates"])
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_threats_for_specific_version(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        v1_resp = await client.get(f"/projects/{project_id}/system-model/versions/1/threats")
        assert v1_resp.status_code == 200

        missing_resp = await client.get(f"/projects/{project_id}/system-model/versions/99/threats")
        assert missing_resp.status_code == 404
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_linddun_present_when_pii_asset_exists(client, tmp_path):
    from app.main import app

    prose_with_pii_asset = json.dumps(
        {
            "components": [],
            "actors": [],
            "flows": [],
            "assets": [
                {
                    "name": "Card Token",
                    "classification": "pii",
                    "owner_name": "Payment Processor",
                    "confidence": 0.9,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "trust_zones": [],
            "declared_controls": [],
        }
    )
    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(
        tmp_path, respond=lambda _p: prose_with_pii_asset
    )
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        threats_resp = await client.get(f"/projects/{project_id}/system-model/threats")
        body = threats_resp.json()
        assert body["linddun_present"] is True
        processor_row = next(r for r in body["matrix"] if r["element_name"] == "Payment Processor")
        assert len(processor_row["linddun_categories"]) == 7
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
