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
    Gateway --> Historian[SCADA Historian]
```

We store the card token here.
"""

CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()

# GV.OC-01.02 ("Stakeholder alignment") is real fixture data carrying one
# resolved regulatory reference (TESTREG-A) and one deliberately
# unresolvable one (TESTREG-UNKNOWN, absent from the fixture's own Catalog
# of Mapped Documents sheet) — chosen over PR.AA-05.01 (used by the Task 15
# mitigation API tests) specifically so this test can exercise real
# regulatory-reference resolution end to end, including the "silently skip
# what the catalog can't resolve" behavior.
_TECHNIQUE = TechniqueChunk(
    id="T1565",
    matrix="enterprise",
    name="Stakeholder Alignment Compromise",
    tactics=("initial-access",),
    description=(
        "Adversaries may tamper with data in transit via a man in the middle attack, "
        "modify data to affect integrity, undermining stakeholder alignment."
    ),
    detection="",
    platforms=("Linux",),
    data_sources=(),
    relationships={"capec": ("CAPEC-176",), "d3fend_inferred": ("D3-STK",)},
)

_D3FEND_CATALOG = [
    D3fendTechnique(
        id="D3-STK",
        tactic="Harden",
        name="Stakeholder Alignment Review",
        depth=0,
        parent_id=None,
        definition="Reviewing stakeholder alignment to reduce risk.",
    )
]


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


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
                        "name": "Stakeholder Alignment Review",
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


async def _freeze_project(
    client, tmp_path, app, *, business_criticality="high", with_control: bool, with_kb: bool = True
):
    if with_kb:
        _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _override_fake_gateway(tmp_path, with_control)
    try:
        resp = await client.post(
            "/projects",
            json={**VALID_PROJECT, "business_criticality": business_criticality},
        )
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    return project_id


async def _upload_cri(client, project_id):
    return await client.post(
        f"/projects/{project_id}/cri-profile",
        files={
            "file": (
                "sample_cri_profile.xlsx",
                CRI_FIXTURE_BYTES,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )


@pytest.mark.asyncio
async def test_risk_register_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.get(f"/projects/{project_id}/system-model/risk-register")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_risk_register_for_missing_project_is_404(client):
    result = await client.get("/projects/does-not-exist/system-model/risk-register")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_risk_register_is_degraded_when_no_cri_profile_uploaded(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=False)
    resp = await client.get(f"/projects/{project_id}/system-model/risk-register")
    assert resp.status_code == 200
    body = resp.json()
    assert body["degraded"] is True
    assert body["tier"] is None
    assert body["csf_rollup"] == []
    for finding in body["findings"]:
        assert finding["csf_functions"] == []
        assert finding["regulatory_exposure"] == []
        assert finding["factors"]["cri_gap_count"] == 0
        assert finding["factors"]["statement_density"] == 0.0
        assert finding["score"] > 0  # likelihood/impact-only assessment, still meaningful


@pytest.mark.asyncio
async def test_risk_register_resolves_regulatory_exposure_and_reports_gap_when_control_absent(
    client, tmp_path
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=False)
    upload = await _upload_cri(client, project_id)
    assert upload.status_code == 200

    resp = await client.get(f"/projects/{project_id}/system-model/risk-register")
    assert resp.status_code == 200
    body = resp.json()
    assert body["degraded"] is False

    finding = next(f for f in body["findings"] if "T1565" in f["technique_ids"])
    assert finding["factors"]["cri_mapping_absent"] is False
    assert finding["factors"]["statement_density"] == 1.0
    assert finding["factors"]["d3fend_gap_count"] == 1
    assert finding["csf_functions"] == ["GV"]

    # TESTREG-A resolves against the fixture's real Catalog of Mapped
    # Documents; TESTREG-UNKNOWN (also referenced by this statement) is not
    # in that catalog and must be silently skipped, never fabricated.
    assert finding["regulatory_exposure"] == [
        {
            "short_code": "TESTREG-A",
            "document_name": "Test Regulation A",
            "issuing_organization": "Test Regulatory Authority A",
        }
    ]

    rollup = next(r for r in body["csf_rollup"] if r["function"] == "GV")
    assert rollup["unsatisfied_statement_count"] == 1
    assert rollup["unsatisfied_density"] == 1.0


@pytest.mark.asyncio
async def test_risk_register_reports_no_gap_when_control_present(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=True)
    await _upload_cri(client, project_id)

    resp = await client.get(f"/projects/{project_id}/system-model/risk-register")
    body = resp.json()
    finding = next(f for f in body["findings"] if "T1565" in f["technique_ids"])
    assert finding["factors"]["statement_density"] == 0.0
    assert finding["factors"]["d3fend_gap_count"] == 0
    assert finding["regulatory_exposure"] == []


@pytest.mark.asyncio
async def test_higher_business_criticality_increases_the_same_finding_score(client, tmp_path):
    from app.main import app

    low_project_id = await _freeze_project(
        client, tmp_path, app, business_criticality="low", with_control=False
    )
    await _upload_cri(client, low_project_id)
    low_resp = await client.get(f"/projects/{low_project_id}/system-model/risk-register")
    low_finding = next(
        f for f in low_resp.json()["findings"] if "T1565" in f["technique_ids"]
    )

    critical_project_id = await _freeze_project(
        client, tmp_path, app, business_criticality="critical", with_control=False, with_kb=False
    )
    await _upload_cri(client, critical_project_id)
    critical_resp = await client.get(
        f"/projects/{critical_project_id}/system-model/risk-register"
    )
    critical_finding = next(
        f for f in critical_resp.json()["findings"] if "T1565" in f["technique_ids"]
    )

    assert critical_finding["factors"]["likelihood"] == low_finding["factors"]["likelihood"]
    assert critical_finding["factors"]["impact_weight"] > low_finding["factors"]["impact_weight"]
    assert critical_finding["score"] > low_finding["score"]


@pytest.mark.asyncio
async def test_risk_register_degrades_gracefully_with_no_kb_snapshot(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=False, with_kb=False)
    resp = await client.get(f"/projects/{project_id}/system-model/risk-register")
    assert resp.status_code == 200
    body = resp.json()
    assert body["findings"] == []
    assert body["csf_rollup"] == []


@pytest.mark.asyncio
async def test_risk_register_for_specific_version(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_control=False)

    v1_resp = await client.get(f"/projects/{project_id}/system-model/versions/1/risk-register")
    assert v1_resp.status_code == 200

    missing_resp = await client.get(
        f"/projects/{project_id}/system-model/versions/99/risk-register"
    )
    assert missing_resp.status_code == 404
