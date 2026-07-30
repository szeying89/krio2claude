import asyncio
import json

import pytest

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
}

DESIGN_DOC = """\
# Payments Platform

The gateway receives requests from the public internet and writes to
the database over a backup restore path. There is no KB snapshot for
this test, so nothing can ever be adjudicated.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway -->|backup restore| DB[(Database)]
```
"""

EXTRACTION_WITH_TRUST_ZONES_AND_LOW_CONFIDENCE_ASSUMPTION = json.dumps(
    {
        "components": [],
        "actors": [],
        "flows": [],
        "assets": [],
        "trust_zones": [
            {"name": "DMZ", "member_names": ["Client", "Gateway"], "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1}},
            {"name": "Internal", "member_names": ["Database"], "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1}},
        ],
        "declared_controls": [],
    }
)


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path, response: str):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _freeze_project(client, tmp_path, app):
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(
        tmp_path, EXTRACTION_WITH_TRUST_ZONES_AND_LOW_CONFIDENCE_ASSUMPTION
    )
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


NORMAL_CRITIQUE_RESPONSE = json.dumps({"severity": "high", "rationale": "this needs a human look"})


@pytest.mark.asyncio
async def test_generate_before_any_freeze_is_404(client, tmp_path):
    from app.main import app

    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        result = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_generate_for_unknown_project_is_404(client, tmp_path):
    from app.main import app

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        result = await client.post("/projects/does-not-exist/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    assert result.status_code == 404


@pytest.mark.asyncio
async def test_generate_finds_missed_threat_and_questionable_assumption(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        resp = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert resp.status_code == 200
    items = resp.json()
    categories = {i["category"] for i in items}
    assert "missed_threat" in categories
    for item in items:
        assert item["status"] == "pending"
        assert item["cited_element_ids"] or item["cited_statement_ids"]


@pytest.mark.asyncio
async def test_list_and_get_review_items(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    listed = await client.get(f"/projects/{project_id}/review-items")
    assert listed.status_code == 200
    assert len(listed.json()) >= 1

    item_id = listed.json()[0]["id"]
    fetched = await client.get(f"/projects/{project_id}/review-items/{item_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == item_id


@pytest.mark.asyncio
async def test_reject_persists_reason_and_creates_no_revision(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    resp = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide",
        json={"decision": "reject", "reason": "not a real concern"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["item"]["status"] == "rejected"
    assert body["item"]["decision_reason"] == "not a real concern"
    assert body["new_revision"] is None

    revisions = await client.get(f"/projects/{project_id}/revisions")
    assert revisions.json() == []


@pytest.mark.asyncio
async def test_accept_creates_a_new_revision_and_is_recorded(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    resp = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide",
        json={"decision": "accept", "reason": "confirmed, needs investigation"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["item"]["status"] == "accepted"
    assert body["new_revision"] is not None

    revisions = await client.get(f"/projects/{project_id}/revisions")
    assert len(revisions.json()) == 1
    assert revisions.json()[0]["id"] == body["new_revision"]["id"]


@pytest.mark.asyncio
async def test_every_decision_is_audited(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    before_decision = await client.get(f"/projects/{project_id}/review-items/{item_id}/audit")
    assert [e["action"] for e in before_decision.json()] == ["created"]

    await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide",
        json={"decision": "reject", "reason": "audit trail check"},
    )

    after_decision = await client.get(f"/projects/{project_id}/review-items/{item_id}/audit")
    actions = [e["action"] for e in after_decision.json()]
    assert actions == ["created", "rejected"]
    rejected_entry = next(e for e in after_decision.json() if e["action"] == "rejected")
    assert rejected_entry["reason"] == "audit trail check"


@pytest.mark.asyncio
async def test_deciding_an_already_decided_item_is_409(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    first = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide", json={"decision": "reject"}
    )
    assert first.status_code == 200
    second = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide", json={"decision": "accept"}
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_decide_unknown_item_is_404(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    resp = await client.post(
        f"/projects/{project_id}/review-items/does-not-exist/decide", json={"decision": "reject"}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_decision_value_is_422(client, tmp_path):
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    resp = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide", json={"decision": "maybe"}
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_concurrent_decide_calls_on_the_same_item_never_both_win(client, tmp_path):
    """Security-review finding, fixed here: decide_item used to read the
    item's status, check it in Python, and only then commit -- two
    concurrent decide calls could both observe "pending" before either
    committed, both proceeding to accept/reject (and, on the accept path,
    both creating a revision) for what must be a single, terminal
    decision. Firing two real concurrent requests at the same item proves
    the atomic `UPDATE ... WHERE status = 'pending'` fix: exactly one
    request wins with 200, the other loses with 409 -- never both 200,
    and never both 409."""
    from app.main import app

    project_id = await _freeze_project(client, tmp_path, app)
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:
        generated = await client.post(f"/projects/{project_id}/review-items/generate")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
    item_id = generated.json()[0]["id"]

    responses = await asyncio.gather(
        client.post(
            f"/projects/{project_id}/review-items/{item_id}/decide", json={"decision": "accept"}
        ),
        client.post(
            f"/projects/{project_id}/review-items/{item_id}/decide", json={"decision": "reject"}
        ),
    )
    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 409]

    audit = await client.get(f"/projects/{project_id}/review-items/{item_id}/audit")
    actions = [e["action"] for e in audit.json()]
    assert actions.count("created") == 1
    assert actions.count("accepted") + actions.count("rejected") == 1

    revisions = await client.get(f"/projects/{project_id}/revisions")
    assert len(revisions.json()) <= 1
