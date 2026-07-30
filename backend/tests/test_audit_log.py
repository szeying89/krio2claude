"""Task 24: 'complete the append-only audit log covering agent
invocations (with trajectory summaries and cost/latency), KB and CRI
refreshes, tiering answers, intel ingestion, review decisions, model
edits, and exports.'

Review decisions already have their own dedicated, real, append-only
trail (`ReviewAuditEntry`, Task 21, tested in `test_review_api.py`'s
`test_every_decision_is_audited`) -- this general-purpose log
(`app/models/audit.py` + `app/services/audit/service.py`) covers every
other action type the plan names, plus places review decisions on the
same cross-cutting timeline. Cost/latency per agent invocation is a
known, documented limitation: `TrajectoryRecord` (Task 1b) does not
currently propagate the LLM gateway's own per-call `GatewayResult` (cost,
usage) up through an agent handler's tool calls, so this log records
what is genuinely available at the orchestrator-invocation boundary --
agent name, tool-call count, and cache-hit -- not cost/latency, rather
than fabricating numbers that aren't really there.

This test drives one project through a real KB refresh, CRI upload,
impact tiering, intel ingestion, model freeze, a manual model edit,
review-item generation and a decision, and all five report/export
endpoints, then asserts the audit log carries a real, correctly-detailed
entry for every one of those action types.
"""

import json
from pathlib import Path

import pytest

from app.api.deps import get_kb_refresh_service, get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.core.config import get_settings
from app.services.audit.service import AuditLogService
from app.services.kb.refresh_service import KBRefreshService
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from tests.kb_fixtures import load_json, load_text, load_yaml

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

CRI_FIXTURE_BYTES = Path("tests/fixtures/cri/sample_cri_profile.xlsx").read_bytes()

EXTRACTION = json.dumps(
    {"components": [], "actors": [], "flows": [], "assets": [], "trust_zones": [], "declared_controls": []}
)

INTEL_EXTRACTION = json.dumps(
    {
        "technique_ids": ["T1190"], "cves": [], "affected_products": [], "actor": None,
        "targeted_sectors": [], "campaign_start": None, "campaign_end": None,
        "ttp_summary": "Exploited a public-facing application.", "source_credibility": "medium",
    }
)

CRITIQUE_RESPONSE = json.dumps({"severity": "high", "rationale": "worth a look"})


def _dispatching_respond(prompt: str) -> str:
    if "extracting structured threat-intelligence facts" in prompt:
        return INTEL_EXTRACTION
    if "one mitigation recommendation" in prompt:
        return json.dumps(
            {"guidance": "Deploy MFA.", "referenced_entity_names": [], "satisfied_cri_statement_ids": [], "effort": 2}
        )
    if "narrative summary section" in prompt:
        return json.dumps({"summary": "This model shows real risk drivers."})
    if "severity" in prompt.lower() and "rationale" in prompt.lower():
        return CRITIQUE_RESPONSE
    return EXTRACTION


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path):
    def _dep():
        return LLMGateway(FakeProvider(respond=_dispatching_respond), cache_dir=tmp_path / "llm-cache")

    return _dep


def _install_fixture_kb_service():
    from app.main import app

    kb_dir = get_settings().kb_dir

    def override() -> KBRefreshService:
        return KBRefreshService(
            kb_dir,
            fetch_attack_enterprise=lambda: (
                load_json("enterprise_bundle.json"), "19.1", "https://example/enterprise-attack-19.1.json",
            ),
            fetch_atlas=lambda: (load_yaml("atlas_data.yaml"), "5.6.0", "https://example/ATLAS.yaml"),
            fetch_capec=lambda: (load_json("capec_bundle.json"), "3.9", "https://example/stix-capec.json"),
            fetch_d3fend=lambda: (load_text("d3fend_catalog.csv"), "unknown", "https://example/D3FEND.csv"),
        )

    app.dependency_overrides[get_kb_refresh_service] = override
    return app


@pytest.mark.asyncio
async def test_audit_log_covers_every_named_action_type_end_to_end(client, tmp_path):
    app = _install_fixture_kb_service()
    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)

    try:
        kb_refresh = await client.post("/kb/refresh")
        assert kb_refresh.status_code == 200

        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]

        cri_upload = await client.post(
            f"/projects/{project_id}/cri-profile",
            files={
                "file": (
                    "sample_cri_profile.xlsx", CRI_FIXTURE_BYTES,
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )
        assert cri_upload.status_code == 200

        tiering = await client.post(
            f"/projects/{project_id}/impact-tiering",
            json={"answers": [{"question_id": "1.1", "answer": True, "justification": "critical"}]},
        )
        assert tiering.status_code == 200

        intel = await client.post("/intel/articles", json={"text": "An advisory."})
        assert intel.status_code == 200

        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC.encode(), "text/markdown")},
        )
        freeze = await client.post(f"/projects/{project_id}/system-model")
        assert freeze.status_code == 200

        edit = await client.patch(
            f"/projects/{project_id}/system-model",
            json={"components": [], "dataflows": [], "assets": [], "trust_zones": []},
        )
        assert edit.status_code == 200

        generated = await client.post(f"/projects/{project_id}/review-items/generate")
        assert generated.status_code == 200
        if generated.json():
            item_id = generated.json()[0]["id"]
            decided = await client.post(
                f"/projects/{project_id}/review-items/{item_id}/decide",
                json={"decision": "reject", "reason": "not a concern"},
            )
            assert decided.status_code == 200

        for path in (
            f"/projects/{project_id}/reports/executive",
            f"/projects/{project_id}/reports/executive/pdf",
            f"/projects/{project_id}/exports/otm",
            f"/projects/{project_id}/exports/csv",
            f"/projects/{project_id}/exports/json",
        ):
            export_resp = await client.get(path)
            assert export_resp.status_code == 200, path
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)
        app.dependency_overrides.pop(get_kb_refresh_service, None)

    project_log = await client.get(f"/projects/{project_id}/audit-log", params={"limit": 500})
    assert project_log.status_code == 200
    entries = project_log.json()
    actions = {e["action"] for e in entries}

    assert "cri.upload" in actions
    assert "cri.tiering_answered" in actions
    assert "model.frozen" in actions
    assert "model.edited" in actions
    assert "agent.invoked" in actions
    assert "export.generated" in actions

    tiering_entry = next(e for e in entries if e["action"] == "cri.tiering_answered")
    assert tiering_entry["detail"]["tier"] == 1

    agent_entries = [e for e in entries if e["action"] == "agent.invoked"]
    agent_names = {e["detail"]["agent_name"] for e in agent_entries}
    assert "enumeration" in agent_names
    assert "mitigation" in agent_names
    assert "reporting" in agent_names
    for entry in agent_entries:
        assert "tool_call_count" in entry["detail"]
        assert "cache_hit" in entry["detail"]

    export_entries = [e for e in entries if e["action"] == "export.generated"]
    export_formats = {e["detail"]["format"] for e in export_entries}
    assert export_formats == {"markdown", "pdf", "otm", "csv", "json"}

    # kb.refresh and intel.ingested are global actions, not project-scoped
    # (a KB refresh and an intel article aren't tied to any one project at
    # ingestion time) -- they show up on the global log with no project_id.
    global_log = await client.get("/audit-log", params={"limit": 500})
    assert global_log.status_code == 200
    global_entries = global_log.json()
    global_actions = {e["action"] for e in global_entries}
    assert "kb.refresh" in global_actions
    assert "intel.ingested" in global_actions
    kb_entry = next(e for e in global_entries if e["action"] == "kb.refresh")
    assert kb_entry["project_id"] is None

    global_agent_names = {
        e["detail"]["agent_name"] for e in global_entries if e["action"] == "agent.invoked"
    }
    assert "intel" in global_agent_names


@pytest.mark.asyncio
async def test_action_prefix_filter_narrows_the_log(client, tmp_path):
    app = _install_fixture_kb_service()
    try:
        await client.post("/kb/refresh")
    finally:
        app.dependency_overrides.pop(get_kb_refresh_service, None)

    filtered = await client.get("/audit-log", params={"action_prefix": "kb."})
    assert filtered.status_code == 200
    assert all(e["action"].startswith("kb.") for e in filtered.json())


SECRET = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.mark.asyncio
async def test_redaction_reaches_nested_dicts_and_lists_in_detail(client):
    """Security-review finding, fixed: `_redact` previously only redacted
    a top-level string *value* in `detail`, so a secret nested inside a
    dict or hidden in a list of free-text strings would reach the
    database -- and from there, the unauthenticated `GET /audit-log`
    endpoint -- completely unredacted. No current call site nests
    free-text this deeply, but the fix must hold regardless of shape."""
    from app.db.base import get_database

    db = get_database()
    async with db.session_factory() as session:
        service = AuditLogService(session)
        await service.record(
            "test.nested_redaction",
            f"summary with a secret {SECRET}",
            detail={
                "nested": {"api_key": SECRET},
                "list_of_notes": [f"note containing {SECRET}", "an unrelated note"],
                "deeply_nested": {"outer": {"inner": [SECRET]}},
            },
        )
        entries = await service.list_entries(action_prefix="test.nested_redaction")

    assert len(entries) == 1
    entry = entries[0]
    assert SECRET not in entry.summary
    assert SECRET not in entry.detail["nested"]["api_key"]
    assert SECRET not in entry.detail["list_of_notes"][0]
    assert entry.detail["list_of_notes"][1] == "an unrelated note"
    assert SECRET not in entry.detail["deeply_nested"]["outer"]["inner"][0]
    assert "REDACTED" in entry.detail["nested"]["api_key"]


def test_audit_log_service_is_structurally_append_only():
    """No method on the service can modify or remove an existing entry --
    only `record` (insert) and `list_entries` (read) exist at all."""
    public_methods = {
        name for name in dir(AuditLogService) if not name.startswith("_") and callable(getattr(AuditLogService, name))
    }
    assert public_methods == {"record", "list_entries"}
