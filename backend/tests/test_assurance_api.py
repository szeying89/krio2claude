import json
from pathlib import Path

import pytest

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.core.config import get_settings
from app.services.kb.d3fend import D3fendTechnique
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
to the payment processor over HTTPS.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway --> Processor[(Payment Processor)]
```
"""

CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()

_TECHNIQUE = TechniqueChunk(
    id="T1190",
    matrix="enterprise",
    name="Privileged Access Control Bypass",
    tactics=("initial-access",),
    description=(
        "Adversaries may tamper with data in transit via a man in the middle attack, "
        "modify data to affect integrity, bypassing privileged access control."
    ),
    detection="",
    platforms=("Linux",),
    data_sources=(),
    relationships={"capec": ("CAPEC-176",), "d3fend_inferred": ("D3-PAM",)},
)

_D3FEND_CATALOG = [
    D3fendTechnique(
        id="D3-PAM", tactic="Harden", name="Privileged Account Management", depth=0,
        parent_id=None, definition="Managing privileged access to reduce risk.",
    )
]

EXTRACTION = json.dumps(
    {
        "components": [],
        "actors": [],
        "flows": [],
        "assets": [
            {
                "name": "Card Token", "classification": "confidential", "owner_name": "Payment Processor",
                "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1},
            }
        ],
        "trust_zones": [],
        "declared_controls": [],
    }
)


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _write_kb_snapshot(kb_dir):
    return write_kb_snapshot(
        kb_dir, [_TECHNIQUE], versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-01-01T00:00:00Z", d3fend_catalog=_D3FEND_CATALOG,
    )


def _gateway_dep(tmp_path, response: str):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project(client, tmp_path, app, with_kb: bool = True):
    if with_kb:
        _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
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


@pytest.mark.asyncio
async def test_confidence_before_any_freeze_is_404(client, tmp_path):
    from app.main import app

    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:
        result = await client.get(f"/projects/{project_id}/system-model/confidence")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_confidence_for_unknown_project_is_404(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:
        result = await client.get("/projects/does-not-exist/system-model/confidence")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_confidence_report_has_six_dimensions_and_a_valid_band(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    await client.post(
        f"/projects/{project_id}/cri-profile",
        files={"file": ("sample_cri_profile.xlsx", CRI_FIXTURE_BYTES, "application/octet-stream")},
    )

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:
        resp = await client.get(f"/projects/{project_id}/system-model/confidence")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["dimensions"]) == 6
    assert {d["name"] for d in body["dimensions"]} == {
        "element_coverage", "cell_adjudication_rate", "grounding_rate",
        "cri_mapping_completeness", "unresolved_assumptions", "limitations_completeness",
    }
    assert 0.0 <= body["overall_score"] <= 100.0
    assert body["band"] in {"Low", "Moderate", "High"}
    for dim in body["dimensions"]:
        assert 0.0 <= dim["score"] <= 100.0
        assert dim["weight"] == pytest.approx(1 / 6)


@pytest.mark.asyncio
async def test_confidence_degrades_gracefully_with_no_kb_snapshot(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=False)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:
        resp = await client.get(f"/projects/{project_id}/system-model/confidence")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert resp.status_code == 200
    body = resp.json()
    cri_dim = next(d for d in body["dimensions"] if d["name"] == "cri_mapping_completeness")
    assert cri_dim["score"] == 100.0  # no gaps at all -> vacuously complete


@pytest.mark.asyncio
async def test_confidence_for_specific_version(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:
        v1_resp = await client.get(f"/projects/{project_id}/system-model/versions/1/confidence")
        assert v1_resp.status_code == 200

        missing_resp = await client.get(
            f"/projects/{project_id}/system-model/versions/99/confidence"
        )
        assert missing_resp.status_code == 404
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
