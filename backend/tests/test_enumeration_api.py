import json

import pytest

from app.api import enumeration as enumeration_module
from app.api.deps import get_llm_gateway
from app.core.config import get_settings
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import write_snapshot as write_kb_snapshot
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    enumeration_module._technique_indexes.clear()
    yield
    enumeration_module._technique_indexes.clear()


def _write_capec_mapped_kb_snapshot(kb_dir):
    chunks = [
        TechniqueChunk(
            id="T1499",
            matrix="enterprise",
            name="Endpoint Denial of Service",
            tactics=("impact",),
            description="Adversaries may perform denial of service attacks to degrade or "
            "block availability by flooding a target to exhaust resources.",
            detection="",
            platforms=("Linux",),
            data_sources=(),
            relationships={"capec": ("CAPEC-125",)},
        ),
        TechniqueChunk(
            id="AML.T0015",
            matrix="atlas",
            name="ML Model Denial of Service",
            tactics=("impact",),
            description="Adversaries may flood an ML inference endpoint to exhaust compute "
            "and deny service.",
            detection="",
            platforms=(),
            data_sources=(),
            relationships={"capec": ("CAPEC-125",)},
        ),
    ]
    return write_kb_snapshot(
        kb_dir,
        chunks,
        versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={},
        fetched_at="2026-01-01T00:00:00Z",
    )

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


@pytest.mark.asyncio
async def test_atlas_proposal_fires_on_ml_platform_indicators(client, tmp_path):
    from app.main import app

    ml_doc = """\
# ML Platform

The training pipeline retrains the fraud model nightly. Requests reach
the model serving inference endpoint over HTTPS.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Endpoint[Model Inference Endpoint]
    Endpoint --> Store[(Feature Store)]
```
"""
    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("ml.md", ml_doc.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        proposal_resp = await client.get(f"/projects/{project_id}/atlas-proposal")
        assert proposal_resp.status_code == 200
        body = proposal_resp.json()
        assert body["proposed"] is True
        assert body["atlas_enabled"] is False
        assert any(f["category"] == "inference_endpoint" for f in body["findings"])
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_atlas_proposal_silent_on_pure_it_design(client, tmp_path):
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

        proposal_resp = await client.get(f"/projects/{project_id}/atlas-proposal")
        assert proposal_resp.json()["proposed"] is False
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_unconfirmed_atlas_proposal_has_no_effect_on_bridge(client, tmp_path):
    from app.main import app

    kb_dir = get_settings().kb_dir
    _write_capec_mapped_kb_snapshot(kb_dir)

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        # never confirmed — atlas_enabled stays false, so no ATLAS technique
        # may appear anywhere in the bridged output
        threats_resp = await client.get(f"/projects/{project_id}/system-model/threats")
        body = threats_resp.json()
        assert body["atlas_enabled"] is False
        all_matrices = {
            t["matrix"] for c in body["candidates"] for t in c["bridged_techniques"]
        }
        assert "atlas" not in all_matrices
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_confirming_atlas_expands_the_bridge_to_include_atlas_techniques(client, tmp_path):
    from app.main import app

    kb_dir = get_settings().kb_dir
    _write_capec_mapped_kb_snapshot(kb_dir)

    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        confirm_resp = await client.post(
            f"/projects/{project_id}/atlas-confirmation", json={"enabled": True}
        )
        assert confirm_resp.status_code == 200
        assert confirm_resp.json()["atlas_enabled"] is True

        threats_resp = await client.get(f"/projects/{project_id}/system-model/threats")
        body = threats_resp.json()
        assert body["atlas_enabled"] is True
        all_technique_ids = {
            t["technique_id"] for c in body["candidates"] for t in c["bridged_techniques"]
        }
        assert "AML.T0015" in all_technique_ids
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_capec_bridge_attaches_real_capec_ids_to_stride_candidates(client, tmp_path):
    from app.main import app

    kb_dir = get_settings().kb_dir
    _write_capec_mapped_kb_snapshot(kb_dir)

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
        body = threats_resp.json()
        dos_candidates = [c for c in body["candidates"] if c["category"] == "denial_of_service"]
        assert dos_candidates
        bridged = [t for c in dos_candidates for t in c["bridged_techniques"]]
        assert any(t["technique_id"] == "T1499" and t["capec_ids"] == ["CAPEC-125"] for t in bridged)
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)


@pytest.mark.asyncio
async def test_atlas_confirmation_missing_project_404(client):
    resp = await client.post(
        "/projects/does-not-exist/atlas-confirmation", json={"enabled": True}
    )
    assert resp.status_code == 404
