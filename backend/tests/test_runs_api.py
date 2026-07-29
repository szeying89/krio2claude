import asyncio
import json

import pytest


@pytest.mark.asyncio
async def test_create_and_fetch_run(client):
    resp = await client.post(
        "/runs", json={"stage_names": ["ingest", "enumerate"], "project_name": "demo"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert [s["name"] for s in body["stages"]] == ["ingest", "enumerate"]
    assert all(s["status"] == "pending" for s in body["stages"])

    run_id = body["id"]
    fetched = await client.get(f"/runs/{run_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == run_id


@pytest.mark.asyncio
async def test_create_run_provisions_artifact_directory(client, tmp_path):
    resp = await client.post("/runs", json={"stage_names": ["ingest"]})
    run_id = resp.json()["id"]
    assert (tmp_path / "data" / "runs" / run_id).is_dir()


@pytest.mark.asyncio
async def test_get_missing_run_404(client):
    resp = await client.get("/runs/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_illegal_run_transition_rejected_via_api(client):
    resp = await client.post("/runs", json={"stage_names": ["ingest"]})
    run_id = resp.json()["id"]

    # queued -> complete is illegal; must go through running first
    bad = await client.post(f"/runs/{run_id}/transition", json={"status": "complete"})
    assert bad.status_code == 409

    ok = await client.post(f"/runs/{run_id}/transition", json={"status": "running"})
    assert ok.status_code == 200
    assert ok.json()["status"] == "running"


@pytest.mark.asyncio
async def test_stage_transition_via_api(client):
    resp = await client.post("/runs", json={"stage_names": ["ingest"]})
    run = resp.json()
    run_id = run["id"]
    stage_id = run["stages"][0]["id"]

    await client.post(f"/runs/{run_id}/transition", json={"status": "running"})

    started = await client.post(
        f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "running"}
    )
    assert started.status_code == 200
    assert started.json()["status"] == "running"

    done = await client.post(
        f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "complete"}
    )
    assert done.status_code == 200
    assert done.json()["status"] == "complete"

    # terminal stage state: re-transitioning is illegal
    illegal = await client.post(
        f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "running"}
    )
    assert illegal.status_code == 409


@pytest.mark.asyncio
async def test_sse_stage_events_stream_live(client):
    resp = await client.post("/runs", json={"stage_names": ["ingest"]})
    run = resp.json()
    run_id = run["id"]
    stage_id = run["stages"][0]["id"]

    received: list[dict] = []

    async def read_events():
        async with client.stream("GET", f"/runs/{run_id}/events") as stream:
            async for line in stream.aiter_lines():
                if line.startswith("data:"):
                    received.append(json.loads(line[len("data:") :].strip()))
                if len(received) >= 3:
                    return

    reader = asyncio.create_task(read_events())
    await asyncio.sleep(0.05)  # let the SSE subscriber attach before events fire

    await client.post(f"/runs/{run_id}/transition", json={"status": "running"})
    await client.post(
        f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "running"}
    )
    await client.post(
        f"/runs/{run_id}/stages/{stage_id}/transition", json={"status": "complete"}
    )
    await client.post(f"/runs/{run_id}/transition", json={"status": "complete"})

    await asyncio.wait_for(reader, timeout=5)

    assert received[0] == {
        "type": "run_status",
        "run_id": run_id,
        "status": "running",
        "at": received[0]["at"],
    }
    assert received[1]["type"] == "stage_status"
    assert received[1]["status"] == "running"
    assert received[2]["status"] == "complete"
    assert received[2]["stage_id"] == stage_id
