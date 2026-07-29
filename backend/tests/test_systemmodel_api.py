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
async def test_get_system_model_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.get(f"/projects/{project_id}/system-model")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_freeze_creates_version_1_with_out_of_scope_detection(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )

        freeze_resp = await client.post(f"/projects/{project_id}/system-model")
        assert freeze_resp.status_code == 200
        model = freeze_resp.json()
        assert model["version"] == 1
        assert model["parent_version"] is None

        historian = next(c for c in model["components"] if "Historian" in c["name"])
        assert historian["out_of_scope"] is True
        assert len(model["out_of_scope"]) == 1
        assert model["out_of_scope"][0]["category"] == "ot_ics"

        latest = await client.get(f"/projects/{project_id}/system-model")
        assert latest.json()["version"] == 1
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_refreezing_creates_version_2_with_diff(client, tmp_path):
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
        second = await client.post(f"/projects/{project_id}/system-model")
        assert second.status_code == 200
        model = second.json()
        assert model["version"] == 2
        assert model["parent_version"] == 1

        versions = await client.get(f"/projects/{project_id}/system-model/versions")
        assert versions.json() == [1, 2]

        v1 = await client.get(f"/projects/{project_id}/system-model/versions/1")
        assert v1.status_code == 200
        assert v1.json()["version"] == 1
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_patch_edits_create_new_version_with_user_asserted_provenance(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        frozen = await client.post(f"/projects/{project_id}/system-model")
        gateway_component = next(c for c in frozen.json()["components"] if c["name"] == "Gateway")

        patch_resp = await client.patch(
            f"/projects/{project_id}/system-model",
            json={"components": [{"id": gateway_component["id"], "kind": "datastore"}]},
        )
        assert patch_resp.status_code == 200
        updated = patch_resp.json()
        assert updated["version"] == 2
        assert updated["parent_version"] == 1
        edited = next(c for c in updated["components"] if c["id"] == gateway_component["id"])
        assert edited["kind"] == "datastore"
        assert edited["provenance"] == "user_asserted"
        assert any("changed component" in line for line in updated["change_summary"])
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_patch_edit_unknown_element_is_422(client, tmp_path):
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

        patch_resp = await client.patch(
            f"/projects/{project_id}/system-model",
            json={"components": [{"id": "does-not-exist", "kind": "datastore"}]},
        )
        assert patch_resp.status_code == 422
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_otm_export_round_trips_and_is_valid_json(client, tmp_path):
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

        otm_resp = await client.get(f"/projects/{project_id}/system-model/otm")
        assert otm_resp.status_code == 200
        otm = otm_resp.json()
        assert otm["otmVersion"] == "0.2.0"
        assert len(otm["components"]) >= 1
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_mermaid_render_endpoint(client, tmp_path):
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

        mermaid_resp = await client.get(f"/projects/{project_id}/system-model/mermaid")
        assert mermaid_resp.status_code == 200
        source = mermaid_resp.json()["source"]
        assert "graph TD" in source
        assert "Gateway" in source
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
