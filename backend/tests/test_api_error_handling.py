"""Professional unit-test audit finding: the exception-translation
branches in app/api/reports.py and app/api/review.py (attack-graph /
path-enumeration budget errors -> 422) were never exercised by any test
in the suite -- the underlying budget-raising logic is well-covered at
the service layer (test_enumeration_attack_graph.py,
test_enumeration_path_enumeration.py), but "does the API layer actually
translate that exception into the documented HTTP status code, or does
it 500 uncaught" was unverified. Constructing a system model large
enough to genuinely exhaust the real 500-node/2000-edge budget would be
expensive and not actually test anything more than the mapping itself,
so this uses targeted fault injection (monkeypatching the imported
`build_attack_graph` symbol each module holds its own reference to) to
force the exact exception at the exact call site and verify the
translation is correct.
"""

import json

import pytest

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.core.config import get_settings
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError
from app.services.enumeration.path_enumeration import PathEnumerationBudgetExceededError
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

EXTRACTION = json.dumps(
    {"components": [], "actors": [], "flows": [], "assets": [], "trust_zones": [], "declared_controls": []}
)

_TECHNIQUE = TechniqueChunk(
    id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
    tactics=("initial-access",),
    description="tamper with data in transit via a man in the middle attack",
    detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-176",)},
)
_D3FEND_CATALOG = [
    D3fendTechnique(id="D3-PAM", tactic="Harden", name="Privileged Account Management", depth=0, parent_id=None, definition="x")
]


def _write_kb_snapshot(kb_dir):
    return write_kb_snapshot(
        kb_dir, [_TECHNIQUE], versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-01-01T00:00:00Z", d3fend_catalog=_D3FEND_CATALOG,
    )


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: EXTRACTION), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project(client, tmp_path, app):
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
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    return project_id


@pytest.mark.asyncio
async def test_reports_endpoint_translates_attack_graph_budget_error_to_422(
    client, tmp_path, monkeypatch
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    def _raise_budget_exceeded(*_args, **_kwargs):
        raise AttackGraphBudgetExceededError("node", 1)

    monkeypatch.setattr("app.api.reports.build_attack_graph", _raise_budget_exceeded)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.get(f"/projects/{project_id}/reports/executive")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 422
    assert "node" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reports_endpoint_translates_path_enumeration_budget_error_to_422(
    client, tmp_path, monkeypatch
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    def _raise_budget_exceeded(*_args, **_kwargs):
        raise PathEnumerationBudgetExceededError(5000)

    monkeypatch.setattr("app.api.reports.enumerate_paths", _raise_budget_exceeded)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.get(f"/projects/{project_id}/exports/csv")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_review_generate_translates_attack_graph_budget_error_to_422(
    client, tmp_path, monkeypatch
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    def _raise_budget_exceeded(*_args, **_kwargs):
        raise AttackGraphBudgetExceededError("edge", 2000)

    monkeypatch.setattr("app.api.review.build_attack_graph", _raise_budget_exceeded)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 422
    assert "edge" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_review_generate_translates_path_enumeration_budget_error_to_422(
    client, tmp_path, monkeypatch
):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    def _raise_budget_exceeded(*_args, **_kwargs):
        raise PathEnumerationBudgetExceededError(5000)

    monkeypatch.setattr("app.api.review.enumerate_paths", _raise_budget_exceeded)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
    try:
        resp = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 422
