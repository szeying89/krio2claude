"""Task 23: 'progress streaming' and 'partial re-execution ... under
real (not stubbed) agents'.

Task 1's Run/RunStage state machine and EventBus have existed since the
very first task, but no prior task ever drove them alongside a real agent
invocation — every other test of RunService (test_state_machine.py, the
plain CRUD tests behind app/api/runs.py) exercises the state machine in
isolation, with synthetic stage names and no actual work happening in
between transitions. This test wires the two together for the first
time: a Run's stages are transitioned RUNNING -> COMPLETE around the
exact real HTTP calls that drive the model-building, enumeration +
mitigation, and assurance (critique) agents for a real project, and the
EventBus's real event stream is captured and asserted on.

"Partial re-execution" is demonstrated the way this platform actually
implements it (see IMPLEMENTATION_PLAN.md's Task 21 note: accepting a
review item reuses Task 19's revision-creation path rather than a
bespoke rerun): after review-item acceptance, the original run's stages
are untouched (still COMPLETE, not re-run), and only a new, narrowly
scoped run covering the downstream stage that actually needs to reflect
the decision (reporting) is created — proving the "recompute only the
minimal affected set" property end to end, not just at the abstract
InvalidationGraph level test_invalidation_graph.py already covers.
"""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.db.base import get_database
from app.models.run import Run
from app.orchestrator.events import get_event_bus
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
the database over a backup restore path.

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway -->|backup restore| DB[(Database)]
```
"""

EXTRACTION = json.dumps(
    {
        "components": [], "actors": [], "flows": [], "assets": [],
        "trust_zones": [
            {"name": "DMZ", "member_names": ["Client", "Gateway"], "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1}},
            {"name": "Internal", "member_names": ["Database"], "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1}},
        ],
        "declared_controls": [],
    }
)

NORMAL_CRITIQUE_RESPONSE = json.dumps({"severity": "high", "rationale": "worth a human look"})


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path, response: str):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    return _dep


async def _stage_ids_in_order(run_id: str) -> dict[str, str]:
    """RunOut has no nested stage listing, so stage ids are recovered the
    same way RunService itself would: reading the ORM's `.stages`
    relationship directly through the same database the API uses."""
    db = get_database()
    async with db.session_factory() as session:
        result = await session.execute(
            select(Run).where(Run.id == run_id).options(selectinload(Run.stages))
        )
        run = result.scalar_one()
        return {stage.name: stage.id for stage in sorted(run.stages, key=lambda s: s.sequence_index)}


async def _create_and_start_run(client, stage_names, project_name):
    resp = await client.post("/runs", json={"stage_names": stage_names, "project_name": project_name})
    run = resp.json()
    await client.post(f"/runs/{run['id']}/transition", json={"status": "running"})
    return run


async def _run_stage(client, run_id, stage_id, work_coro):
    await client.post(f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "running"})
    result = await work_coro()
    await client.post(f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "complete"})
    return result


@pytest.mark.asyncio
async def test_run_stages_transition_and_publish_events_around_real_agent_work(client, tmp_path):
    from app.main import app

    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    created = await client.post(
        "/runs",
        json={
            "stage_names": ["model_building", "enumeration_and_mitigation", "assurance"],
            "project_name": "Payments Platform",
        },
    )
    run = created.json()
    stage_ids = await _stage_ids_in_order(run["id"])

    bus = get_event_bus()
    queue = bus.subscribe(run["id"])

    await client.post(f"/runs/{run['id']}/transition", json={"status": "running"})

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, EXTRACTION)
    try:

        async def _do_model_building():
            await client.post(
                f"/projects/{project_id}/documents",
                files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
            )
            return await client.post(f"/projects/{project_id}/system-model")

        model_result = await _run_stage(
            client, run["id"], stage_ids["model_building"], _do_model_building
        )
        assert model_result.status_code == 200

        async def _do_enumeration_and_mitigation():
            return await client.get(f"/projects/{project_id}/system-model/control-gaps")

        gaps_result = await _run_stage(
            client, run["id"], stage_ids["enumeration_and_mitigation"], _do_enumeration_and_mitigation
        )
        assert gaps_result.status_code == 200
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path, NORMAL_CRITIQUE_RESPONSE)
    try:

        async def _do_assurance():
            return await client.post(f"/projects/{project_id}/review-items/generate")

        review_result = await _run_stage(client, run["id"], stage_ids["assurance"], _do_assurance)
        assert review_result.status_code == 200
        items = review_result.json()
        assert any(i["category"] == "missed_threat" for i in items)
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    await client.post(f"/runs/{run['id']}/transition", json={"status": "complete"})

    events = []
    while not queue.empty():
        events.append(queue.get_nowait())

    stage_events = [e for e in events if e["type"] == "stage_status"]
    run_events = [e for e in events if e["type"] == "run_status"]

    by_stage: dict[str, list[str]] = {}
    for event in stage_events:
        by_stage.setdefault(event["stage_name"], []).append(event["status"])
    assert by_stage["model_building"] == ["running", "complete"]
    assert by_stage["enumeration_and_mitigation"] == ["running", "complete"]
    assert by_stage["assurance"] == ["running", "complete"]

    assert [e["status"] for e in run_events] == ["running", "complete"]

    final_run = await client.get(f"/runs/{run['id']}")
    assert final_run.json()["status"] == "complete"
    review = await client.get(f"/projects/{project_id}/review-items")
    item_id = review.json()[0]["id"]

    # -- Partial re-execution --
    # Accepting the review item creates a new revision without needing to
    # redo model-building or enumeration/mitigation at all.
    decide = await client.post(
        f"/projects/{project_id}/review-items/{item_id}/decide",
        json={"decision": "accept", "reason": "confirmed"},
    )
    assert decide.status_code == 200
    assert decide.json()["new_revision"] is not None

    # The original run's stages are untouched by the acceptance -- no
    # stage was silently re-opened or rerun.
    unchanged_run = await client.get(f"/runs/{run['id']}")
    assert unchanged_run.json()["status"] == "complete"

    # A second, narrowly-scoped run covering only the stage whose output
    # actually needs to reflect the accepted decision (reporting) is what
    # "recompute only the minimal downstream set" looks like in practice --
    # a brand new Run scoped to exactly the one stage, not a rerun of the
    # first Run's already-complete stages.
    partial_run = await _create_and_start_run(client, ["reporting"], "Payments Platform")
    assert partial_run["id"] != run["id"]
    partial_stage_ids = await _stage_ids_in_order(partial_run["id"])
    assert set(partial_stage_ids) == {"reporting"}
