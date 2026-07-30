"""Security-review fix: an opt-in, enforced API-key gate
(app/api/auth.py::require_api_key), wired as a global FastAPI dependency
so it applies to every route without touching each router individually.
`TM_API_KEY` unset (the default, and every other test file's assumption)
preserves this build's original no-auth-in-v1 behavior exactly -- these
tests are the only ones in the suite that set it.
"""

import pytest


@pytest.mark.asyncio
async def test_requests_succeed_without_a_key_when_api_key_is_unset(client):
    """The default, pre-existing behavior every other test in this suite
    relies on -- explicitly asserted here so a future change to the
    default is caught immediately."""
    resp = await client.get("/projects")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_request_without_a_key_is_rejected_once_api_key_is_set(client, monkeypatch):
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    resp = await client.get("/projects")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_request_with_the_wrong_key_is_rejected(client, monkeypatch):
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    resp = await client.get("/projects", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_request_with_the_correct_key_succeeds(client, monkeypatch):
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    resp = await client.get("/projects", headers={"X-API-Key": "s3cret-test-key"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_key_check_applies_globally_not_just_to_one_router(client, monkeypatch):
    """The gate is wired once, at the app level -- spot-check a handful
    of routers registered at very different points in create_app() to
    confirm none of them were missed."""
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    paths = ("/projects", "/runs/nonexistent-id", "/kb/snapshots", "/audit-log", "/intel/articles/" + "0" * 64)
    for path in paths:
        resp = await client.get(path)
        assert resp.status_code == 401, path

    for path in paths:
        resp = await client.get(path, headers={"X-API-Key": "s3cret-test-key"})
        assert resp.status_code != 401, path


def test_docs_routes_are_enabled_when_api_key_is_unset(monkeypatch):
    """The default, pre-existing behavior: docs stay on when there is no
    gate to bypass in the first place."""
    monkeypatch.delenv("TM_API_KEY", raising=False)
    from app.main import create_app

    app = create_app()
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"


def test_docs_routes_are_disabled_once_api_key_is_set(monkeypatch):
    """Security-review finding, fixed here: /docs, /redoc, and /openapi.json
    are plain Starlette routes added by FastAPI's own setup(), outside the
    dependency-injection tree entirely -- the app-level
    dependencies=[Depends(require_api_key)] can never gate them. Once an
    operator actually turns the key gate on, the full API schema must not
    still be reachable by anyone -- verified here by constructing the app
    fresh (the module-level `app.main.app` singleton bakes in whatever
    TM_API_KEY was set at first import, so this must call create_app()
    directly rather than go through the shared `client` fixture)."""
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    from app.main import create_app

    app = create_app()
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


@pytest.mark.asyncio
async def test_openapi_json_is_unreachable_over_http_once_api_key_is_set(monkeypatch):
    """End-to-end confirmation, not just the app-object check above: a real
    request to /openapi.json 404s once the gate is on, instead of handing
    back the full API schema with no key at all."""
    monkeypatch.setenv("TM_API_KEY", "s3cret-test-key")
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for path in ("/openapi.json", "/docs", "/redoc"):
            resp = await ac.get(path)
            assert resp.status_code == 404, path
