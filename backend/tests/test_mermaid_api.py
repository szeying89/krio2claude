import pytest


@pytest.mark.asyncio
async def test_parse_valid_diagram_returns_structure(client):
    src = "graph TD\n  A[Start] --> B{Decision}\n  B -->|Yes| C[End]\n"
    resp = await client.post("/mermaid/parse", json={"source": src})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["diagram_type"] == "flowchart"
    assert body["direction"] == "TD"
    assert {n["id"] for n in body["nodes"]} == {"A", "B", "C"}
    assert len(body["edges"]) == 2
    assert body["normalized_source"].startswith("graph TD")


@pytest.mark.asyncio
async def test_parse_invalid_diagram_returns_error_panel(client):
    resp = await client.post("/mermaid/parse", json={"source": "A --> B\n"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] is not None
    assert body["error_line"] == 1
    assert body["nodes"] == []


@pytest.mark.asyncio
async def test_parse_c4_diagram(client):
    src = 'C4Context\n  Person(a, "Alice")\n  System(b, "App")\n  Rel(a, b, "Uses")\n'
    resp = await client.post("/mermaid/parse", json={"source": src})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["diagram_type"] == "c4context"
