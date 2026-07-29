import pytest

from tests.pdf_fixture import build_minimal_pdf

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
    "data_classifications": ["pii", "financial"],
    "compliance_regimes": ["pci-dss"],
    "scope_statements": ["Excludes third-party payment processor internals"],
    "declared_controls": ["mTLS between services"],
}

DESIGN_DOC = """\
# Payments Platform

The gateway receives requests from the public internet and forwards them
to the payment processor.

```mermaid
flowchart LR
    Client -->|HTTPS| Gateway
    Gateway --> Processor[(Payment Processor)]
```

The processor stores no card data at rest.
"""


@pytest.mark.asyncio
async def test_create_and_fetch_project(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Payments Platform"
    assert body["business_criticality"] == "high"
    assert body["system_class"] == "it"
    assert body["documents"] == []

    project_id = body["id"]
    fetched = await client.get(f"/projects/{project_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == project_id


@pytest.mark.asyncio
async def test_list_projects(client):
    await client.post("/projects", json=VALID_PROJECT)
    await client.post("/projects", json={**VALID_PROJECT, "name": "Second Project"})

    resp = await client.get("/projects")
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert names == {"Payments Platform", "Second Project"}


@pytest.mark.asyncio
async def test_get_missing_project_404(client):
    resp = await client.get("/projects/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project_partial_fields(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    updated = await client.patch(f"/projects/{project_id}", json={"name": "Renamed"})
    assert updated.status_code == 200
    body = updated.json()
    assert body["name"] == "Renamed"
    assert body["business_criticality"] == "high"  # untouched fields survive


@pytest.mark.asyncio
async def test_delete_project(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    deleted = await client.delete(f"/projects/{project_id}")
    assert deleted.status_code == 204

    missing = await client.get(f"/projects/{project_id}")
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_upload_markdown_with_embedded_diagram(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    upload = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
    )
    assert upload.status_code == 200
    body = upload.json()

    assert body["filename"] == "design.md"
    assert len(body["mermaid_blocks"]) == 1
    assert "Client -->|HTTPS| Gateway" in body["mermaid_blocks"][0]["source"]
    assert "flowchart LR" not in body["extracted_prose"]
    assert "The processor stores no card data at rest." in body["extracted_prose"]
    assert "gateway receives requests" in body["extracted_prose"]

    # the saved project context (side-by-side with the extracted document) is intact
    project = await client.get(f"/projects/{project_id}")
    assert len(project.json()["documents"]) == 1


@pytest.mark.asyncio
async def test_upload_hash_is_stable_for_identical_content(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    first = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("v1.md", b"# same content", "text/markdown")},
    )
    second = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("v2.md", b"# same content", "text/markdown")},
    )

    assert first.json()["sha256"] == second.json()["sha256"]
    assert first.json()["sha256"] != ""


@pytest.mark.asyncio
async def test_upload_pdf_extracts_text(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    pdf_bytes = build_minimal_pdf("Confidential Design")
    upload = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("design.pdf", pdf_bytes, "application/pdf")},
    )
    assert upload.status_code == 200
    assert "Confidential Design" in upload.json()["extracted_prose"]


@pytest.mark.asyncio
async def test_upload_rejects_oversized_file(client, monkeypatch):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    monkeypatch.setenv("TM_MAX_UPLOAD_BYTES", "10")
    upload = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("big.md", b"x" * 1000, "text/markdown")},
    )
    assert upload.status_code == 422


@pytest.mark.asyncio
async def test_upload_rejects_wrong_type(client):
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    upload = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("virus.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert upload.status_code == 422


@pytest.mark.asyncio
async def test_upload_to_missing_project_404(client):
    upload = await client.post(
        "/projects/does-not-exist/documents",
        files={"file": ("design.md", b"# hi", "text/markdown")},
    )
    assert upload.status_code == 404


@pytest.mark.asyncio
async def test_multi_block_and_nested_mermaid_fences(client):
    doc = """\
Wrapper below is not mermaid itself (4 backticks), so the inner fenced
example must not be extracted as a real diagram.

````text
```mermaid
graph TD; FAKE-->BLOCK
```
````

```mermaid
graph TD; A-->B
```

```mmd
flowchart LR; C-->D
```
"""
    resp = await client.post("/projects", json=VALID_PROJECT)
    project_id = resp.json()["id"]

    upload = await client.post(
        f"/projects/{project_id}/documents",
        files={"file": ("multi.md", doc.encode(), "text/markdown")},
    )
    blocks = upload.json()["mermaid_blocks"]
    assert len(blocks) == 2
    assert "A-->B" in blocks[0]["source"]
    assert "C-->D" in blocks[1]["source"]
    assert not any("FAKE" in b["source"] for b in blocks)
