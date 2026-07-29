import json
from pathlib import Path

import pytest

from app.api import mitigation as mitigation_module
from app.api.deps import get_llm_gateway
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
    Gateway --> Historian[SCADA Historian]
```

We store the card token here.
"""

CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    mitigation_module._technique_indexes.clear()
    yield
    mitigation_module._technique_indexes.clear()

# A single technique whose name/description was deliberately picked to
# lexically bridge against both a D3FEND countermeasure and a real CRI
# diagnostic statement in the sample fixture ("PR.AA-05.01: ... privileged
# access control"), and whose description strongly matches the "tampering"
# STRIDE category's search terms so it reliably bridges via retrieval
# against a single-technique corpus.
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
        id="D3-PAM",
        tactic="Harden",
        name="Privileged Account Management",
        depth=0,
        parent_id=None,
        definition="Managing privileged access to reduce risk.",
    )
]


def _write_kb_snapshot(kb_dir):
    return write_kb_snapshot(
        kb_dir,
        [_TECHNIQUE],
        versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={},
        fetched_at="2026-01-01T00:00:00Z",
        d3fend_catalog=_D3FEND_CATALOG,
    )


def _extraction(with_control: bool) -> str:
    return json.dumps(
        {
            "components": [],
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
            "declared_controls": (
                [
                    {
                        "name": "Privileged Access Management",
                        "applies_to_names": ["Gateway"],
                        "confidence": 0.9,
                        "source_span": {"start_line": 1, "end_line": 1},
                    }
                ]
                if with_control
                else []
            ),
        }
    )


def _override_fake_gateway(tmp_path, with_control: bool):
    def _dep():
        provider = FakeProvider(respond=lambda _p: _extraction(with_control))
        return LLMGateway(provider, cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project(client, tmp_path, app, *, with_control: bool, with_kb: bool = True):
    if with_kb:
        _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path, with_control)
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
async def test_control_gaps_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_control_gaps_for_missing_project_is_404(client):
    result = await client.get("/projects/does-not-exist/system-model/control-gaps")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_control_gaps_degrades_gracefully_with_no_kb_snapshot(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=True, with_kb=False)
    resp = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] is None
    assert body["control_inventory"] == []
    assert body["technique_gaps"] == []


@pytest.mark.asyncio
async def test_control_gaps_degrades_gracefully_with_no_cri_profile_uploaded(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=True)
    resp = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert resp.status_code == 200
    body = resp.json()
    gap = next(g for g in body["technique_gaps"] if g["technique_id"] == "T1190")
    assert gap["cri_mapping_absent"] is True
    assert gap["cri_in_tier_statement_ids"] == []
    assert gap["cri_gap_statement_ids"] == []


@pytest.mark.asyncio
async def test_control_gaps_reports_full_coverage_on_both_tracks_when_control_present(
    client, tmp_path
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=True)
    upload = await client.post(
        f"/projects/{project_id}/cri-profile",
        files={
            "file": (
                "sample_cri_profile.xlsx",
                CRI_FIXTURE_BYTES,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert upload.status_code == 200

    resp = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] is None

    entry = next(
        e for e in body["control_inventory"] if e["control_name"] == "Privileged Access Management"
    )
    assert entry["d3fend_ids"] == ["D3-PAM"]
    assert entry["cri_statement_ids"] == ["PR.AA-05.01"]

    gap = next(g for g in body["technique_gaps"] if g["technique_id"] == "T1190")
    assert gap["d3fend_required_ids"] == ["D3-PAM"]
    assert gap["d3fend_observed_ids"] == ["D3-PAM"]
    assert gap["d3fend_gap_ids"] == []
    assert gap["cri_mapping_absent"] is False
    assert gap["cri_in_tier_statement_ids"] == ["PR.AA-05.01"]
    assert gap["cri_gap_statement_ids"] == []


@pytest.mark.asyncio
async def test_control_gaps_reports_gaps_on_both_tracks_when_control_absent(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=False)
    await client.post(
        f"/projects/{project_id}/cri-profile",
        files={
            "file": (
                "sample_cri_profile.xlsx",
                CRI_FIXTURE_BYTES,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )

    resp = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert resp.status_code == 200
    body = resp.json()
    assert body["control_inventory"] == []

    gap = next(g for g in body["technique_gaps"] if g["technique_id"] == "T1190")
    assert gap["d3fend_gap_ids"] == ["D3-PAM"]
    assert gap["cri_mapping_absent"] is False
    assert gap["cri_gap_statement_ids"] == ["PR.AA-05.01"]


@pytest.mark.asyncio
async def test_control_gaps_for_specific_version(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=True)

    v1_resp = await client.get(f"/projects/{project_id}/system-model/versions/1/control-gaps")
    assert v1_resp.status_code == 200

    missing_resp = await client.get(
        f"/projects/{project_id}/system-model/versions/99/control-gaps"
    )
    assert missing_resp.status_code == 404
