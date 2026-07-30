"""Task 23: 'KB or CRI snapshot change alters output and is attributed as
such'.

Two different KB snapshots are written to the same `kb_dir` (each its own
content-hashed directory, per Task 3 — `latest_snapshot_dir` picks
whichever has the newer `fetched_at`), and the same frozen system model
is re-evaluated against each. The control-gap output must differ in a
way directly explained by what changed between the two snapshots (an
extra D3FEND countermeasure requirement added to the same technique), and
each revision created against a snapshot must carry that exact snapshot's
own content hash — never the other one's, and never blank — so the
change is attributable, not just "different by coincidence."
"""

import json

import pytest

from app.api.deps import get_llm_gateway
from app.api.gap_context import clear_technique_index_cache
from app.core.config import get_settings
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import write_snapshot as write_kb_snapshot
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway

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

EXTRACTION = json.dumps(
    {
        "components": [], "actors": [], "flows": [],
        # An asset owned by "Payment Processor" is what makes it a crown jewel --
        # path enumeration's targets are crown jewels, not just any
        # datastore -- without this, zero paths are ever found and
        # technique_gaps is always empty regardless of which KB snapshot
        # is pinned.
        "assets": [
            {
                "name": "Card Token", "classification": "confidential", "owner_name": "Payment Processor",
                "confidence": 0.9, "source_span": {"start_line": 1, "end_line": 1},
            }
        ],
        "trust_zones": [], "declared_controls": [],
    }
)

_D3_PAM = D3fendTechnique(
    id="D3-PAM", tactic="Harden", name="Privileged Account Management", depth=0,
    parent_id=None, definition="Managing privileged access to reduce risk.",
)
_D3_MFA = D3fendTechnique(
    id="D3-MFA", tactic="Harden", name="Multi-factor Authentication", depth=0,
    parent_id=None, definition="Requiring multiple authentication factors.",
)

_DESCRIPTION = (
    "Adversaries may tamper with data in transit via a man in the middle attack, "
    "modify data to affect integrity, bypassing privileged access control."
)


def _technique_v1() -> TechniqueChunk:
    return TechniqueChunk(
        id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
        tactics=("initial-access",), description=_DESCRIPTION, detection="",
        platforms=("Linux",), data_sources=(),
        relationships={"capec": ("CAPEC-176",), "d3fend_inferred": ("D3-PAM",)},
    )


def _technique_v2() -> TechniqueChunk:
    # Same technique, but a newer KB fetch has learned of a second
    # countermeasure requirement for it -- the one real thing that
    # changed between the two snapshots.
    return TechniqueChunk(
        id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
        tactics=("initial-access",), description=_DESCRIPTION, detection="",
        platforms=("Linux",), data_sources=(),
        relationships={"capec": ("CAPEC-176",), "d3fend_inferred": ("D3-PAM", "D3-MFA")},
    )


@pytest.fixture(autouse=True)
def _clear_technique_index_cache():
    clear_technique_index_cache()
    yield
    clear_technique_index_cache()


def _gateway_dep(tmp_path):
    def _dep():
        return LLMGateway(FakeProvider(respond=lambda _p: EXTRACTION), cache_dir=tmp_path / "llm-cache")

    return _dep


@pytest.mark.asyncio
async def test_kb_snapshot_change_alters_control_gaps_and_is_attributed_via_revision_hash(
    client, tmp_path
):
    from app.main import app

    kb_dir = get_settings().kb_dir
    snapshot_v1_dir = write_kb_snapshot(
        kb_dir, [_technique_v1()], versions={"attack_enterprise": "19.1", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-01-01T00:00:00Z", d3fend_catalog=[_D3_PAM],
    )

    app.dependency_overrides[get_llm_gateway] = _gateway_dep(tmp_path)
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

    gaps_v1 = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert gaps_v1.status_code == 200
    gap_v1 = next(g for g in gaps_v1.json()["technique_gaps"] if g["technique_id"] == "T1190")
    assert gap_v1["d3fend_gap_ids"] == ["D3-PAM"]

    revision_v1 = await client.post(f"/projects/{project_id}/revisions", json={})
    assert revision_v1.status_code == 200
    kb_hash_v1 = revision_v1.json()["kb_snapshot_hash"]
    assert kb_hash_v1 == snapshot_v1_dir.name

    # A newer KB fetch: same technique, one more D3FEND requirement.
    # clear_technique_index_cache() at the top of this test already reset
    # the in-process index cache once; the new snapshot's own content
    # hash forms a brand-new cache key regardless, so this is a real
    # re-read, not a stale hit.
    clear_technique_index_cache()
    snapshot_v2_dir = write_kb_snapshot(
        kb_dir, [_technique_v2()], versions={"attack_enterprise": "19.2", "atlas": "5.0"},
        source_urls={}, fetched_at="2026-02-01T00:00:00Z", d3fend_catalog=[_D3_PAM, _D3_MFA],
    )
    assert snapshot_v2_dir != snapshot_v1_dir

    gaps_v2 = await client.get(f"/projects/{project_id}/system-model/control-gaps")
    assert gaps_v2.status_code == 200
    gap_v2 = next(g for g in gaps_v2.json()["technique_gaps"] if g["technique_id"] == "T1190")
    assert set(gap_v2["d3fend_gap_ids"]) == {"D3-PAM", "D3-MFA"}
    assert gap_v2["d3fend_gap_ids"] != gap_v1["d3fend_gap_ids"]

    revision_v2 = await client.post(f"/projects/{project_id}/revisions", json={})
    assert revision_v2.status_code == 200
    kb_hash_v2 = revision_v2.json()["kb_snapshot_hash"]
    assert kb_hash_v2 == snapshot_v2_dir.name
    assert kb_hash_v2 != kb_hash_v1, "each revision must be attributable to its own pinned KB snapshot"

    diff = await client.get(f"/projects/{project_id}/revisions/{revision_v2.json()['id']}/diff")
    assert diff.status_code == 200
