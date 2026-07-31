"""Security-review fix: a minimal in-memory sliding-window rate limiter
(app/api/rate_limit.py::enforce_rate_limit), wired only onto the
LLM-invoking endpoints. `TM_RATE_LIMIT_PER_MINUTE` unset (the default, and
every other test file's assumption) preserves this build's original
unthrottled behavior exactly -- these tests are the only ones in the
suite that set it.
"""

from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from app.api.rate_limit import enforce_rate_limit, reset_rate_limits


class _FakeSettings:
    def __init__(self, limit: int) -> None:
        self.rate_limit_per_minute = limit


@pytest.mark.asyncio
async def test_requests_are_unthrottled_when_rate_limit_is_unset():
    request = Mock()
    request.client.host = "unset-limit-host"
    for _ in range(10):
        await enforce_rate_limit(request)  # must not raise


@pytest.mark.asyncio
async def test_requests_within_the_limit_all_succeed(monkeypatch):
    import app.api.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _FakeSettings(3))
    reset_rate_limits()

    request = Mock()
    request.client.host = "within-limit-host"
    for _ in range(3):
        await enforce_rate_limit(request)  # must not raise

    reset_rate_limits()


@pytest.mark.asyncio
async def test_requests_beyond_the_limit_are_rejected_with_429(monkeypatch):
    import app.api.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _FakeSettings(2))
    reset_rate_limits()

    request = Mock()
    request.client.host = "beyond-limit-host"
    await enforce_rate_limit(request)
    await enforce_rate_limit(request)

    with pytest.raises(HTTPException) as exc_info:
        await enforce_rate_limit(request)
    assert exc_info.value.status_code == 429
    assert exc_info.value.detail == "rate limit exceeded, try again shortly"

    reset_rate_limits()


@pytest.mark.asyncio
async def test_a_real_request_through_the_app_is_unthrottled_by_default(client):
    """End-to-end sanity check with the real app/dependency-injection
    wiring, using a route that doesn't require any project fixtures."""
    resp = await client.get("/projects")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_the_limit_is_tracked_separately_per_client_host(monkeypatch):
    reset_rate_limits()
    import app.api.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _FakeSettings(1))

    request_a = Mock()
    request_a.client.host = "1.1.1.1"
    request_b = Mock()
    request_b.client.host = "2.2.2.2"

    await enforce_rate_limit(request_a)
    await enforce_rate_limit(request_b)  # different host, must not be throttled
    with pytest.raises(HTTPException):
        await enforce_rate_limit(request_a)

    reset_rate_limits()


@pytest.mark.asyncio
async def test_reset_rate_limits_clears_tracked_state(monkeypatch):
    import app.api.rate_limit as rate_limit_module

    monkeypatch.setattr(rate_limit_module, "get_settings", lambda: _FakeSettings(1))

    request = Mock()
    request.client.host = "3.3.3.3"

    await enforce_rate_limit(request)
    reset_rate_limits()
    await enforce_rate_limit(request)  # must not raise: state was cleared

    reset_rate_limits()


@pytest.mark.asyncio
async def test_the_gate_applies_to_all_llm_endpoints_but_not_otm_export():
    """Structural check that the rate limiter is wired onto the intended
    LLM-invoking endpoints and not blanket-applied everywhere."""
    from fastapi.dependencies.utils import get_dependant

    from app.api.assurance import get_confidence_for_version, get_latest_confidence
    from app.api.intel import ingest_article
    from app.api.mitigation import get_latest_mitigation_plan, get_mitigation_plan_for_version
    from app.api.modelbuilding import build_model_draft
    from app.api.reports import (
        get_csv_export,
        get_json_export,
        get_otm_export,
        get_report,
        get_report_pdf,
    )
    from app.api.review import generate_review_items
    from app.api.revisions import create_revision
    from app.api.systemmodel import freeze_system_model

    for endpoint in (
        get_report,
        get_report_pdf,
        get_csv_export,
        get_json_export,
        generate_review_items,
        create_revision,
        build_model_draft,
        freeze_system_model,
        ingest_article,
        get_latest_confidence,
        get_confidence_for_version,
        get_latest_mitigation_plan,
        get_mitigation_plan_for_version,
    ):
        dependant = get_dependant(path="/x", call=endpoint)
        dep_calls = [d.call for d in dependant.dependencies]
        assert enforce_rate_limit in dep_calls, endpoint
        assert dep_calls[0] is enforce_rate_limit, endpoint

    otm_dependant = get_dependant(path="/x", call=get_otm_export)
    otm_dep_calls = [d.call for d in otm_dependant.dependencies]
    assert enforce_rate_limit not in otm_dep_calls
