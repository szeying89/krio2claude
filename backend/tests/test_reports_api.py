import csv
import io
import json
from pathlib import Path

import pytest
from pypdf import PdfReader

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

We store the card token here.
"""

CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()

# Same fixture technique used by test_mitigation_api.py / test_risk_api.py:
# lexically bridges to a D3FEND countermeasure and a real CRI diagnostic
# statement (PR.AA-05.01) in the sample fixture, and its "tampering"-heavy
# description reliably bridges against the single-technique corpus.
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


def _write_kb_snapshot(kb_dir):
    return write_kb_snapshot(
        kb_dir, [_TECHNIQUE], versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-01-01T00:00:00Z", d3fend_catalog=_D3FEND_CATALOG,
    )


def _extraction() -> str:
    return json.dumps(
        {
            "components": [], "actors": [], "flows": [],
            "assets": [
                {
                    "name": "Card Token", "classification": "confidential",
                    "owner_name": "Payment Processor", "confidence": 0.9,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "trust_zones": [], "declared_controls": [],
        }
    )


def _dispatching_respond(prompt: str) -> str:
    """A single FakeProvider `respond` fn shared across every LLM call this
    endpoint makes (prose extraction/model-building, mitigation
    recommendation generation, and reporting narrative generation) —
    dispatched by a distinctive substring each template's own prompt text
    carries, since FakeProvider's `respond(prompt)` sees the real rendered
    prompt for whichever call is in flight."""
    if "one mitigation recommendation" in prompt:
        return json.dumps(
            {"guidance": "Deploy privileged access management.", "referenced_entity_names": [],
             "satisfied_cri_statement_ids": [], "effort": 2}
        )
    if "narrative summary section" in prompt:
        return json.dumps({"summary": "This model shows T1190 as the leading risk driver."})
    return _extraction()


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path):
    def _dep():
        return LLMGateway(FakeProvider(respond=_dispatching_respond), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project(client, tmp_path, app, *, with_kb: bool = True, with_cri: bool = False):
    if with_kb:
        _write_kb_snapshot(get_settings().kb_dir)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")
        if with_cri:
            await client.post(
                f"/projects/{project_id}/cri-profile",
                files={
                    "file": (
                        "sample_cri_profile.xlsx", CRI_FIXTURE_BYTES,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                },
            )
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    return project_id


@pytest.mark.asyncio
async def test_report_before_any_freeze_is_404(client, tmp_path):
    from app.main import app

    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        result = await client.get(f"/projects/{project_id}/reports/executive")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_report_for_unknown_project_is_404(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        result = await client.get("/projects/does-not-exist/reports/executive")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_report_for_unknown_audience_is_404(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=False)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        result = await client.get(f"/projects/{project_id}/reports/marketing")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_all_three_audience_reports_agree_on_shared_numbers(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=True, with_cri=True)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        exec_resp = await client.get(f"/projects/{project_id}/reports/executive")
        ciso_resp = await client.get(f"/projects/{project_id}/reports/ciso")
        tech_resp = await client.get(f"/projects/{project_id}/reports/technical")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert exec_resp.status_code == 200
    assert ciso_resp.status_code == 200
    assert tech_resp.status_code == 200

    exec_md = exec_resp.json()["markdown"]
    ciso_md = ciso_resp.json()["markdown"]
    tech_md = tech_resp.json()["markdown"]

    # Shared confidence line must agree across all three audiences.
    confidence_lines = [line for line in exec_md.splitlines() if line.startswith("**Confidence:**")]
    assert confidence_lines
    confidence_line = confidence_lines[0]
    assert confidence_line in ciso_md
    assert confidence_line in tech_md

    # Shared narrative fact (real technique id) must ground-check clean.
    assert "T1190" in exec_md
    assert "T1190" in tech_md


@pytest.mark.asyncio
async def test_degraded_no_cri_report_omits_cri_sections(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=True, with_cri=False)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        ciso_resp = await client.get(f"/projects/{project_id}/reports/ciso")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert ciso_resp.status_code == 200
    ciso_md = ciso_resp.json()["markdown"]
    assert "CRI Diagnostic Statement Gaps" not in ciso_md
    assert "Regulatory Exposure" not in ciso_md


@pytest.mark.asyncio
async def test_report_pdf_is_valid_and_contains_expected_text(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=True, with_cri=True)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.get(f"/projects/{project_id}/reports/executive/pdf")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    reader = PdfReader(io.BytesIO(resp.content))
    assert len(reader.pages) >= 1
    text = reader.pages[0].extract_text()
    assert "Executive" in text


@pytest.mark.asyncio
async def test_otm_export_before_any_freeze_is_404(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    result = await client.get(f"/projects/{project_id}/exports/otm")
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_otm_export_validates_and_needs_no_llm(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=False)
    # No LLM gateway override in effect here at all: the OTM export must
    # not depend on it.
    resp = await client.get(f"/projects/{project_id}/exports/otm")
    assert resp.status_code == 200
    document = resp.json()
    assert document["otmVersion"] == "0.2.0"
    assert document["project"]["id"] == project_id


@pytest.mark.asyncio
async def test_csv_export_round_trips_findings(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=True, with_cri=True)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.get(f"/projects/{project_id}/exports/csv")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert rows
    assert any("T1190" in row["technique_ids"] for row in rows)


@pytest.mark.asyncio
async def test_json_export_is_parseable_and_contains_key_fields(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app, with_kb=True, with_cri=True)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.get(f"/projects/{project_id}/exports/json")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    body = json.loads(resp.text)
    assert body["project_name"] == "Payments Platform"
    assert body["risk_findings"][0]["technique_ids"] == ["T1190"]
