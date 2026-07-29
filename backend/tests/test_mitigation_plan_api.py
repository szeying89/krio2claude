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

# Same fixture technique as test_mitigation_api.py: bridges via CAPEC into
# the attack graph and lexically bridges (Task 4's heuristic mapping) into
# the real fixture's PR.AA-05.01 ("Privileged access control") statement.
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

EXTRACTION_NO_CONTROL = json.dumps(
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
        "declared_controls": [],
    }
)

RECOMMENDATION_RESPONSE = json.dumps(
    {
        "guidance": "Enable privileged account management on the Gateway.",
        "referenced_entity_names": ["Gateway"],
        "satisfied_cri_statement_ids": ["PR.AA-05.01"],
        "effort": 3,
    }
)


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


def _gateway_dep(tmp_path, response: str):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project_with_gap(client, tmp_path, app):
    _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION_NO_CONTROL)
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
    return project_id


@pytest.mark.asyncio
async def test_mitigation_plan_before_any_freeze_is_404(client, tmp_path):
    from app.main import app

    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION_NO_CONTROL)
    try:
        result = await client.get(f"/projects/{project_id}/system-model/mitigation-plan")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_mitigation_plan_for_missing_project_is_404(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION_NO_CONTROL)
    try:
        result = await client.get("/projects/does-not-exist/system-model/mitigation-plan")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_mitigation_plan_end_to_end_grounded_recommendation(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project_with_gap(client, tmp_path, app)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, RECOMMENDATION_RESPONSE)
    try:
        resp = await client.get(f"/projects/{project_id}/system-model/mitigation-plan")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["recommendations"]) == 1
    rec = body["recommendations"][0]
    assert rec["technique_id"] == "T1190"
    assert rec["d3fend_id"] == "D3-PAM"
    assert rec["cri_statement_ids"] == ["PR.AA-05.01"]
    assert rec["referenced_entity_ids"]  # resolved to the Gateway component's real id
    assert body["rejection_log"] == []

    assert body["residual_risk"]["risk_reduction"] > 0
    assert body["residual_risk"]["residual_total_score"] < body["residual_risk"]["baseline_total_score"]

    assert len(body["roadmap"]) == 1
    phase = body["roadmap"][0]
    assert phase["recommendation_ids"] == [rec["id"]]
    assert phase["diagnostic_statements_closed"] == ["PR.AA-05.01"]


@pytest.mark.asyncio
async def test_mitigation_plan_rejects_fabricated_cri_citation_into_rejection_log(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project_with_gap(client, tmp_path, app)

    fabricated_response = json.dumps(
        {
            "guidance": "Enable privileged account management on the Gateway.",
            "referenced_entity_names": ["Gateway"],
            "satisfied_cri_statement_ids": ["NOT.A.REAL.GAP"],
            "effort": 3,
        }
    )
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, fabricated_response)
    try:
        resp = await client.get(f"/projects/{project_id}/system-model/mitigation-plan")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["recommendations"] == []
    assert len(body["rejection_log"]) == 1
    assert body["rejection_log"][0]["reason_code"] == "uncited_cri_statement"
    assert body["roadmap"] == []


@pytest.mark.asyncio
async def test_mitigation_plan_degrades_gracefully_with_no_kb_snapshot(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION_NO_CONTROL)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        resp = await client.get(f"/projects/{project_id}/system-model/mitigation-plan")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["recommendations"] == []
    assert body["rejection_log"] == []
    assert body["roadmap"] == []
    assert body["residual_risk"]["risk_reduction"] == 0.0


@pytest.mark.asyncio
async def test_mitigation_plan_for_specific_version(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project_with_gap(client, tmp_path, app)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, RECOMMENDATION_RESPONSE)
    try:
        v1_resp = await client.get(f"/projects/{project_id}/system-model/versions/1/mitigation-plan")
        assert v1_resp.status_code == 200

        missing_resp = await client.get(
            f"/projects/{project_id}/system-model/versions/99/mitigation-plan"
        )
        assert missing_resp.status_code == 404
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
