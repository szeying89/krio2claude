"""Security review finding: every KB/CRI/intel snapshot-lookup endpoint
joined its `content_hash` path parameter directly onto a base directory
with no format check. A percent-encoded `%2e%2e` segment reaches
application code as the opaque path-parameter value `".."` (a literal
`..` segment, by contrast, is normalized away by the ASGI stack before
routing even matches it, and never reaches application code at all --
verified below). The resulting path resolves one directory above the
intended snapshot root; every endpoint's own `is_dir()`/`.exists()`
guard passes (the *parent* directory obviously exists), and the request
then crashes several calls deeper with an unhandled `FileNotFoundError`
(observed live as a bare 500, not the clean 404 every one of these
endpoints returns for an ordinary unknown hash) once a loader tries to
read a fixed filename from that unintended directory.

Reproduced live against a running server before the fix (`GET
/kb/snapshots/%2e%2e`, `/cri/snapshots/%2e%2e`, `/intel/articles/%2e%2e`
all returned a bare 500 with a FileNotFoundError in the server log,
confirmed by reading the server's own traceback). The fix is a single
shared format check (`is_valid_content_hash`: must be a 64-character
lowercase hex sha256 digest, which every real content hash in this
system always is) applied before any path join, closing the whole class
of malformed input at one choke point rather than hardening each
consumer's loader individually.
"""

import pytest

# Values that reach the application handler as the literal string shown
# (a bare ".." is excluded here -- Starlette's own routing normalizes it
# away before the request ever matches a route, so it never reaches this
# endpoint's code at all; that's covered by its own test below).
MALFORMED_HASHES = [
    "%2e%2e",  # the literal reproduction of the finding
    "not-a-hash",
    "a" * 63,  # one char short
    "a" * 65,  # one char long
    "A" * 64,  # uppercase not allowed -- a real content hash is always lowercase hex
    "g" * 64,  # non-hex character
]


@pytest.mark.asyncio
async def test_kb_snapshot_rejects_malformed_content_hash(client):
    for value in MALFORMED_HASHES:
        resp = await client.get(f"/kb/snapshots/{value}")
        assert resp.status_code == 404, value
        assert resp.json()["detail"] == "snapshot not found", value


@pytest.mark.asyncio
async def test_cri_snapshot_rejects_malformed_content_hash(client):
    for value in MALFORMED_HASHES:
        resp = await client.get(f"/cri/snapshots/{value}")
        assert resp.status_code == 404, value
        assert resp.json()["detail"] == "snapshot not found", value


@pytest.mark.asyncio
async def test_intel_article_rejects_malformed_content_hash(client):
    for value in MALFORMED_HASHES:
        resp = await client.get(f"/intel/articles/{value}")
        assert resp.status_code == 404, value
        assert resp.json()["detail"] == "article not found", value


@pytest.mark.asyncio
async def test_retrieval_endpoints_reject_malformed_content_hash(client):
    for value in MALFORMED_HASHES:
        kb_resp = await client.get(f"/kb/snapshots/{value}/retrieval", params={"q": "x"})
        assert kb_resp.status_code == 404, value
        assert kb_resp.json()["detail"] == "KB snapshot not found", value

        cri_resp = await client.get(f"/cri/snapshots/{value}/retrieval", params={"q": "x"})
        assert cri_resp.status_code == 404, value
        assert cri_resp.json()["detail"] == "CRI snapshot not found", value


@pytest.mark.asyncio
async def test_revision_creation_rejects_malformed_intel_content_hash(client):
    resp = await client.post(
        "/projects", json={"name": "Demo", "business_criticality": "high", "system_class": "it"}
    )
    project_id = resp.json()["id"]

    for value in MALFORMED_HASHES:
        revision_resp = await client.post(
            f"/projects/{project_id}/revisions",
            json={"intel_article_content_hashes": [value]},
        )
        # 404 (no system model frozen yet, or article not found) is
        # correct either way -- what matters is it's never a 500.
        assert revision_resp.status_code in (404, 422), value


@pytest.mark.asyncio
async def test_bare_dot_dot_segment_never_even_reaches_the_endpoint(client):
    """A literal `..` path segment is collapsed by the ASGI stack before
    routing matches it at all, so it 404s at the framework level with a
    generic message -- documented here as the reason `..` itself is
    excluded from the malformed-hash sweep above, and as a check that
    this normalization (part of what keeps the finding's blast radius
    narrow) hasn't silently changed.
    """
    resp = await client.get("/kb/snapshots/..")
    assert resp.status_code == 404
