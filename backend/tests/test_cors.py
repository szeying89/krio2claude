"""Task 24: 'strict CORS allowlist' -- a real allowlist (never a
wildcard), since this is a local, single-tenant, no-auth v1 (Requirement
1) and the only legitimate cross-origin caller is the bundled React/TS
frontend's own dev server."""

import pytest

from app.core.config import get_settings


@pytest.mark.asyncio
async def test_allowed_origin_gets_the_cors_header_echoed_back(client):
    settings = get_settings()
    allowed_origin = settings.cors_allowed_origins[0]

    resp = await client.get("/projects", headers={"Origin": allowed_origin})

    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == allowed_origin


@pytest.mark.asyncio
async def test_disallowed_origin_gets_no_cors_header(client):
    resp = await client.get("/projects", headers={"Origin": "http://evil.example.com"})

    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.asyncio
async def test_credentials_are_never_allowed_cross_origin(client):
    settings = get_settings()
    allowed_origin = settings.cors_allowed_origins[0]

    resp = await client.get("/projects", headers={"Origin": allowed_origin})

    assert "access-control-allow-credentials" not in resp.headers


def test_cors_allowlist_is_not_a_wildcard():
    settings = get_settings()
    assert "*" not in settings.cors_allowed_origins
    assert all(origin.startswith(("http://localhost", "http://127.0.0.1")) for origin in settings.cors_allowed_origins)
