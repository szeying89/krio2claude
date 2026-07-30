from pathlib import Path

import pytest

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
}

FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()


async def _create_project(client) -> str:
    resp = await client.post("/projects", json=VALID_PROJECT)
    return resp.json()["id"]


@pytest.mark.asyncio
async def test_upload_cri_profile_and_fetch_manifest(client):
    project_id = await _create_project(client)

    upload = await client.post(
        f"/projects/{project_id}/cri-profile",
        files={
            "file": (
                "sample_cri_profile.xlsx",
                FIXTURE_BYTES,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert upload.status_code == 200
    manifest = upload.json()
    assert manifest["statement_count"] == 3
    assert manifest["tier_counts"] == {"1": 3, "2": 2, "3": 1, "4": 1}
    assert manifest["unresolved_regulatory_references"] == ["TESTREG-UNKNOWN"]

    fetched = await client.get(f"/projects/{project_id}/cri-profile")
    assert fetched.status_code == 200
    assert fetched.json()["content_hash"] == manifest["content_hash"]


@pytest.mark.asyncio
async def test_cri_profile_missing_mode_returns_404(client):
    project_id = await _create_project(client)
    resp = await client.get(f"/projects/{project_id}/cri-profile")
    assert resp.status_code == 404

    stmts = await client.get(f"/projects/{project_id}/cri-profile/statements")
    assert stmts.status_code == 404


@pytest.mark.asyncio
async def test_upload_cri_profile_rejects_oversized_file(client, monkeypatch):
    project_id = await _create_project(client)

    monkeypatch.setenv("TM_MAX_UPLOAD_BYTES", "10")
    upload = await client.post(
        f"/projects/{project_id}/cri-profile",
        files={"file": ("big.xlsx", b"x" * 1000, "application/octet-stream")},
    )
    assert upload.status_code == 422
    assert "exceeds" in upload.json()["detail"]


@pytest.mark.asyncio
async def test_upload_to_missing_project_404(client):
    resp = await client.post(
        "/projects/does-not-exist/cri-profile",
        files={"file": ("x.xlsx", FIXTURE_BYTES, "application/octet-stream")},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_statements_filterable_by_tier(client):
    project_id = await _create_project(client)
    await client.post(
        f"/projects/{project_id}/cri-profile",
        files={"file": ("sample_cri_profile.xlsx", FIXTURE_BYTES, "application/octet-stream")},
    )

    all_statements = await client.get(f"/projects/{project_id}/cri-profile/statements")
    assert len(all_statements.json()) == 3

    tier4_only = await client.get(f"/projects/{project_id}/cri-profile/statements?tier=4")
    ids = {s["profile_id"] for s in tier4_only.json()}
    assert ids == {"GV.OC-01.01"}


@pytest.mark.asyncio
async def test_impact_tiering_submit_and_fetch(client):
    project_id = await _create_project(client)

    answers = [
        {"question_id": qid, "answer": False, "justification": "not applicable"}
        for qid in ("1.1", "1.2", "2.1", "2.2.A", "2.2.B", "3.1", "3.2.A")
    ] + [{"question_id": "2.3", "answer": True, "justification": "processes >5M individuals"}]

    submitted = await client.post(
        f"/projects/{project_id}/impact-tiering", json={"answers": answers}
    )
    assert submitted.status_code == 200
    body = submitted.json()
    assert body["tier"] == 2
    assert body["triggering_question_id"] == "2.3"
    assert len(body["answers"]) == 8

    fetched = await client.get(f"/projects/{project_id}/impact-tiering")
    assert fetched.status_code == 200
    assert fetched.json()["tier"] == 2


@pytest.mark.asyncio
async def test_impact_tiering_not_yet_computed_404(client):
    project_id = await _create_project(client)
    resp = await client.get(f"/projects/{project_id}/impact-tiering")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_impact_tiering_resubmission_replaces_prior_result(client):
    project_id = await _create_project(client)

    first = await client.post(
        f"/projects/{project_id}/impact-tiering",
        json={"answers": [{"question_id": "1.1", "answer": True, "justification": "G-SIB"}]},
    )
    assert first.json()["tier"] == 1

    second = await client.post(
        f"/projects/{project_id}/impact-tiering",
        json={"answers": [{"question_id": "1.1", "answer": False, "justification": "not G-SIB"}]},
    )
    assert second.json()["tier"] == 4

    fetched = await client.get(f"/projects/{project_id}/impact-tiering")
    assert fetched.json()["tier"] == 4
