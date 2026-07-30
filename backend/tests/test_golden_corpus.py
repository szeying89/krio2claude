"""Task 23: golden corpus of 5 reference designs, each with
expected-outcome assertions, run through the real HTTP/DB stack with a
`FakeProvider`-backed LLM gateway (never stubbed at the agent/service
layer) — one per corpus design named in IMPLEMENTATION_PLAN.md's Task 23:
a simple web app, microservices with a third-party integration, an ML
inference platform (ATLAS), a design containing OT elements (out-of-scope
handling), and a financial-services system exercising CRI tiering end to
end. The sixth scenario the task also asks for — an intel-revision
scenario — already has real, passing, end-to-end coverage in
`test_revision_api.py::test_corroborating_intel_revision_raises_path_likelihood_and_shows_in_diff`,
so it is referenced rather than duplicated here.
"""

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

CORPUS_DIR = Path("tests/fixtures/corpus")
CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()

_TECHNIQUE = TechniqueChunk(
    id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
    tactics=("initial-access",),
    description=(
        "Adversaries may tamper with data in transit via a man in the middle attack, "
        "modify data to affect integrity, bypassing privileged access control."
    ),
    detection="", platforms=("Linux",), data_sources=(),
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


EMPTY_EXTRACTION = json.dumps(
    {"components": [], "actors": [], "flows": [], "assets": [], "trust_zones": [], "declared_controls": []}
)


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path, response: str = EMPTY_EXTRACTION):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _create_project(client, *, name, business_criticality="high", system_class="it"):
    resp = await client.post(
        "/projects",
        json={"name": name, "business_criticality": business_criticality, "system_class": system_class},
    )
    assert resp.status_code == 200
    return resp.json()["id"]


async def _upload_and_freeze(client, tmp_path, app, project_id, design_filename, response=EMPTY_EXTRACTION):
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, response)
    try:
        design_text = (CORPUS_DIR / design_filename).read_bytes()
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": (design_filename, design_text, "text/markdown")},
        )
        resp = await client.post(f"/projects/{project_id}/system-model")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.asyncio
async def test_corpus_1_simple_web_app_resolves_cleanly_with_no_out_of_scope(client, tmp_path):
    from app.main import app

    project_id = await _create_project(client, name="Simple Web App")
    model = await _upload_and_freeze(client, tmp_path, app, project_id, "simple_web_app.md")

    names = {c["name"] for c in model["components"]}
    assert names == {"Browser Client", "Web Server", "Application Database"}
    assert model["out_of_scope"] == []

    project = (await client.get(f"/projects/{project_id}")).json()
    assert project["atlas_enabled"] is False


@pytest.mark.asyncio
async def test_corpus_2_microservices_third_party_integration_produces_a_control_gap_view(
    client, tmp_path
):
    from app.main import app

    _write_kb_snapshot(get_settings().kb_dir)
    project_id = await _create_project(client, name="Microservices Backend")
    model = await _upload_and_freeze(client, tmp_path, app, project_id, "microservices_third_party.md")

    names = {c["name"] for c in model["components"]}
    assert names == {
        "Client", "API Gateway", "Order Service", "Payment Service",
        "Third-Party Payment Processor", "Order Database", "Notification Service",
    }
    assert model["out_of_scope"] == []

    resp = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] is None  # no CRI profile attached to this scenario


@pytest.mark.asyncio
async def test_corpus_3_ml_inference_platform_proposes_and_confirms_atlas(client, tmp_path):
    from app.main import app

    project_id = await _create_project(client, name="ML Inference Platform", system_class="ml")
    await _upload_and_freeze(client, tmp_path, app, project_id, "ml_inference_platform.md")

    proposal = await client.get(f"/projects/{project_id}/atlas-proposal")
    assert proposal.status_code == 200
    proposal_body = proposal.json()
    assert proposal_body["proposed"] is True
    assert proposal_body["atlas_enabled"] is False  # detection alone never flips it
    categories = {f["category"] for f in proposal_body["findings"]}
    assert "model_serving" in categories
    assert "training_pipeline" in categories

    confirmation = await client.post(
        f"/projects/{project_id}/atlas-confirmation", json={"enabled": True}
    )
    assert confirmation.status_code == 200
    assert confirmation.json()["atlas_enabled"] is True

    project = (await client.get(f"/projects/{project_id}")).json()
    assert project["atlas_enabled"] is True


@pytest.mark.asyncio
async def test_corpus_4_ot_elements_are_marked_out_of_scope_not_silently_mapped(client, tmp_path):
    from app.main import app

    project_id = await _create_project(client, name="Plant Monitoring Gateway")
    model = await _upload_and_freeze(client, tmp_path, app, project_id, "ot_elements.md")

    historian = next(c for c in model["components"] if c["name"] == "SCADA Historian")
    assert historian["out_of_scope"] is True
    assert "scada" in (historian["out_of_scope_reason"] or "").lower()
    assert len(model["out_of_scope"]) == 1
    declaration = model["out_of_scope"][0]
    assert declaration["category"] == "ot_ics"
    assert declaration["subject_id"] == historian["id"]

    # The rest of the topology is unaffected -- out-of-scope marks the one
    # OT element, it does not remove or hide the surrounding IT elements.
    other_names = {c["name"] for c in model["components"] if c["name"] != "SCADA Historian"}
    assert other_names == {"Corporate Dashboard", "Plant Monitoring Gateway", "Engineering Workstation"}


@pytest.mark.asyncio
async def test_corpus_5_financial_services_cri_tiering_end_to_end(client, tmp_path):
    from app.main import app

    _write_kb_snapshot(get_settings().kb_dir)
    project_id = await _create_project(
        client, name="Core Banking Platform", business_criticality="critical"
    )

    upload = await client.post(
        f"/projects/{project_id}/cri-profile",
        files={
            "file": (
                "sample_cri_profile.xlsx", CRI_FIXTURE_BYTES,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert upload.status_code == 200

    answers = [
        {"question_id": "1.1", "answer": True, "justification": "systemically important financial institution"}
    ] + [
        {"question_id": qid, "answer": False, "justification": "not applicable"}
        for qid in ("1.2", "2.1", "2.2.A", "2.2.B", "2.3", "3.1", "3.2.A", "3.2.B")
    ]
    tiering = await client.post(f"/projects/{project_id}/impact-tiering", json={"answers": answers})
    assert tiering.status_code == 200
    assert tiering.json()["tier"] == 1
    assert tiering.json()["triggering_question_id"] == "1.1"

    model = await _upload_and_freeze(client, tmp_path, app, project_id, "financial_services_cri.md")
    names = {c["name"] for c in model["components"]}
    assert "Core Ledger Service" in names

    control_gaps = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert control_gaps.status_code == 200
    assert control_gaps.json()["tier"] == 1

    risk = await client.get(f"/projects/{project_id}/system-model/risk-register")
    assert risk.status_code == 200
    assert risk.json()["tier"] == 1
