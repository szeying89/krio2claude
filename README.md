# Ground-Truth Threat Modelling Platform

A local, single-tenant threat modelling platform that builds a canonical
system model from a design document, enumerates STRIDE/LINDDUN threats
grounded in real ATT&CK/ATLAS/CAPEC/D3FEND data, assesses risk against a
user-supplied CRI Profile, drafts mitigations, self-critiques its own
output, and produces multi-audience reports and exports — all through an
orchestrator that enforces every hard guarantee (schema, grounding,
fact-provenance, budgets) centrally, never by trusting an autonomous
agent's own restraint. The full task-by-task design record, including
every implementation and test summary, lives in
[`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md); this document is
the operational entry point.

## Scope limitations

- **ATT&CK Enterprise + ATLAS only.** No ICS/OT matrix, no Mobile matrix.
  A design element that looks like OT/ICS equipment (PLC, RTU, SCADA,
  historian, Modbus, DNP3, OPC-UA — see
  `app/services/systemmodel/out_of_scope.py`) is marked
  `out_of_scope: true` with a declared reason, not silently mapped to an
  Enterprise technique and presented as if it were covered. The same
  applies to mobile-client indicators.
- **ATLAS is opt-in.** A deterministic detector
  (`app/services/enumeration/atlas_detector.py`) can *propose* enabling
  ATLAS from ML-platform indicators in the model, but only an explicit
  `POST /projects/{id}/atlas-confirmation` call ever flips it on.
- **No authentication by default.** This is a local, single-tenant tool
  and ships with authentication *off* so every existing workflow and test
  keeps working unmodified — but a real, enforced API-key gate is one
  environment variable away. See "Security" below before running it
  anywhere but your own machine.

## Install and quickstart

Prerequisites: Python 3.12+, Node 20+ (for the frontend), and an
Anthropic or OpenAI API key if you want the LLM-backed agents to do
anything beyond Mermaid-only deterministic parsing.

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Provide credentials one of two ways:
export ANTHROPIC_API_KEY=sk-ant-...           # or OPENAI_API_KEY, with TM_LLM_PROVIDER=openai
# -- or --
python -m keyring set threatmodel-platform anthropic

# Run the server (binds to 127.0.0.1:8000 by default)
python -m app.main
```

```bash
# Frontend (separate terminal)
cd frontend
npm install
npm run dev   # http://localhost:5173, proxies API calls to 127.0.0.1:8000
```

Run the test suite and static checks from `backend/`:

```bash
python -m pytest -q
python -m ruff check .
python -m mypy app
```

### Configuration

All settings are environment variables prefixed `TM_` (see
`app/core/config.py`), or a `backend/.env` file. Notable ones:

| Variable | Default | Purpose |
|---|---|---|
| `TM_HOST` | `127.0.0.1` | Bind address — see security prerequisites |
| `TM_PORT` | `8000` | |
| `TM_ALLOW_NON_LOOPBACK` | `false` | Required to bind beyond loopback at all |
| `TM_DATA_DIR` | `./data` | KB/CRI/intel/project storage root |
| `TM_DATABASE_URL` | `sqlite+aiosqlite:///./app.db` | Only SQLite is supported by the backup/restore tooling below |
| `TM_MAX_UPLOAD_BYTES` | `20971520` (20 MiB) | Enforced on every upload endpoint, checked incrementally while streaming (never buffers an oversized body first) |
| `TM_MAX_REQUEST_BODY_BYTES` | `26214400` (25 MiB) | Ceiling on every request body, JSON included — independent of `TM_MAX_UPLOAD_BYTES` so a low upload-size test/config never collides with it (`app/api/body_size_limit.py`) |
| `TM_CORS_ALLOWED_ORIGINS` | `["http://localhost:5173", "http://127.0.0.1:5173"]` | Strict allowlist — never a wildcard |
| `TM_API_KEY` | unset | Off by default; set to require a matching `X-API-Key` header on every request — see "Security" below |
| `TM_RATE_LIMIT_PER_MINUTE` | unset | Off by default; set to cap requests per client IP on the LLM-invoking endpoints (report/export generation, review-item generation, revision creation) |
| `TM_LLM_PROVIDER` | `anthropic` | `anthropic` \| `openai` |
| `TM_LLM_MODEL` | `claude-sonnet-5` | |

## Refreshing the knowledge base

The MITRE ATT&CK/ATLAS/CAPEC and D3FEND corpora are fetched explicitly,
never implicitly, and land in an immutable, content-hashed snapshot
directory under `data/kb/<content-hash>/` (`app/services/kb/snapshot.py`)
— every run pins one specific snapshot, so results are always
attributable to exactly which corpus version produced them.

```
POST /kb/refresh          # fetch live ATT&CK/ATLAS/CAPEC/D3FEND, write a new snapshot
GET  /kb/snapshots         # list every snapshot ever fetched, newest first
GET  /kb/snapshots/{hash}  # a specific snapshot's manifest
```

Refreshing against unchanged upstream data is a deliberate no-op (same
content hash, nothing new written). Every refresh is recorded in the
append-only audit log (`kb.refresh`, see below) with the resulting
content hash.

D3FEND ships as a real technique catalog with **no authoritative
ATT&CK mapping** (MITRE doesn't publish one). Where no real CRI or
D3FEND mapping exists for a technique, this platform tags the result
`mapping_inferred` — attached by a small, deterministic, versioned
lexical-overlap matcher (`app/services/kb/heuristic_mapping.py`), never
presented as if it were authoritative, and always counted separately in
coverage metrics rather than merged into real mappings.

## CRI Profile workbook: sourcing and licensing

The CRI Profile v2.2 workbook (diagnostic statements, regulatory
mappings, and the impact-tiering questionnaire) is **licensed content
you supply** — this repository does not redistribute it, does not fetch
it from anywhere, and ships no fixture containing the real workbook
(`backend/tests/fixtures/cri/` contains only small, hand-authored
excerpts matching the real column layout, for testing). Obtain the
workbook directly from the Cyber Risk Institute and upload it per
project:

```
POST /projects/{id}/cri-profile        # multipart upload of the .xlsx workbook
GET  /projects/{id}/cri-profile        # manifest: statement/tier counts, unresolved regulatory refs
GET  /projects/{id}/cri-profile/statements?tier=<n>
POST /projects/{id}/impact-tiering     # answer the real 9-question cascading decision tree
GET  /projects/{id}/impact-tiering
```

A project with no CRI workbook uploaded degrades gracefully throughout
the platform (`cri_mapping_absent` on every gap, `has_cri: false` on
every report) rather than failing — CRI-aligned risk assessment is an
enhancement over the ATT&CK/D3FEND baseline, not a hard requirement.

Same as D3FEND, there is no authoritative CRI→ATT&CK mapping published
anywhere; the same `heuristic_mapping.py` matcher bridges CRI diagnostic
statements to techniques via subject tags and statement text, tagged
`mapping_inferred` and never merged with a real mapping.

## Ruleset authoring

STRIDE-per-element and LINDDUN rules are a versioned YAML file, not
code: `app/services/enumeration/rulesets/stride_linddun_v1.yaml`, loaded
by `app/services/enumeration/ruleset.py::load_ruleset`. Shape:

```yaml
version: "1.0.0"

element_rules:
  - match_kind: process          # DFD element kind
    categories: [spoofing, tampering, ...]

  - match_kind: datastore
    match_tag: log                # optional: only applies if the element carries this tag
    categories: [repudiation]

linddun:
  personal_data_classifications: [pii, phi]   # triggers on asset classification, not element kind
  personal_data_tags: [pii, personal-data]
  categories: [linkability, identifiability, ...]
```

Rules for the same `match_kind` are additive. This produces zero LLM
calls end to end (Task 10's own explicit design point) — the Enumeration
Agent calls this as a deterministic tool, never reasons about which
categories apply. To add a new element kind or refine an existing one,
add or edit a rule and bump `version`; nothing else in the pipeline
needs to change, since candidate generation, the CAPEC bridge, and
grounding validation all consume the ruleset's output uniformly.

## Architecture: Orchestrator, Agents, Services

Three kinds of components, kept structurally distinct so agent autonomy
never trades away determinism (full detail and rationale in
`IMPLEMENTATION_PLAN.md`):

- **Orchestrator** (`app/orchestrator/`) — the deterministic control
  plane. Makes no LLM calls itself. Invokes every agent through one
  uniform contract (`Orchestrator.invoke(agent_name, input_artifacts,
  config, pinned_snapshots)`), enforces hard guarantees centrally via a
  `validate` gate that independently re-checks an agent's own output
  (never trusting the agent's verdict), owns a trajectory cache (cache
  hit ⇒ byte-identical output, zero re-computation), a per-agent
  tool-call budget that fails loudly rather than truncating, and the
  dependency/invalidation graph (`compute_affected`) that answers "what
  needs to re-run" from a set of changed artifact types — one mechanism
  behind clarifications, review-item acceptance, and intel revisions
  alike.
- **Agents** — seven real `AgentSpec`s: Model-Building, Enumeration
  (zero LLM calls), Risk & Mitigation, Assurance (adversarial critique),
  Intel, Revision, and Reporting. Each is autonomous *within* its scoped
  toolset, but every deterministic computation (the STRIDE/LINDDUN rule
  engine, the CAPEC bridge, the attack graph, the risk formula, the
  confidence rubric) is exposed to it as a tool it calls, never
  reimplemented as agent judgment — `AgentContext.call_tool` is the only
  channel an agent handler has to affect anything at all.
- **Services** — stateless infrastructure: KB Snapshot, CRI Catalog,
  Retrieval (BM25 + dense + RRF), the LLM Gateway (deterministic-mode
  switch, content-addressed completion cache, schema-validated
  repair-retry loop, pre-send secret redaction), and now the append-only
  audit log.

## Risk and confidence methodology

**Risk** (`app/services/risk/`):
```
Impact     = asset criticality × data classification weight × impact-tier weight × business-function disruption
Likelihood = exposure × inverse required-privilege × technique prevalence × unsatisfied-CRI-statement density × intel uplift
Risk       = Impact × Likelihood, banded, rolled up per NIST CSF 2.0 function (GV/ID/PR/DE/RS/RC)
```
D3FEND gap count never moves the score directly — only unsatisfied CRI
diagnostic-statement density does, since D3FEND is a technical-control
signal and CRI is the control-objective/regulatory signal this formula
is scoped to weight.

**Confidence** (`app/services/assurance/rubric.py`) is a fixed-weight
rubric over six pure, deterministic dimensions (each 1/6): element
coverage, cell-adjudication rate, grounding rate, CRI-mapping
completeness, unresolved-assumption penalty, and limitations
completeness. It takes **no intel-related input at all** — a structural
guarantee that attaching a threat-intel article never moves the
confidence score, because confidence answers "how good is this model,"
not "how fresh is the threat landscape." A separate Threat Landscape
Currency indicator (age of newest intel, corroborated-path count,
ignored-as-irrelevant count) answers that second question instead.

## Intel handling and its trust model

An attached article or advisory is **data, never instruction, by
construction**: fetched through an SSRF-hardened client (blocks
loopback/RFC1918/link-local addresses including the `169.254.169.254`
cloud-metadata address, revalidates every redirect hop, caps redirect
count and response size, forwards no credentials — see
`app/services/intel/ssrf_guard.py` and `fetch.py`), hashed and stored
verbatim, and only ever fed to the LLM as a quoted, typed field inside a
schema-validated extraction prompt — never as free-form instructions the
model's reasoning loop could be steered by. Any imperative-looking
content in the source (`app/services/intel/injection_guard.py`) is
flagged as a prompt-injection indicator, logged, and otherwise ignored.
Extracted content can only ever populate typed fields (technique IDs,
CVEs, affected products, actor, sectors, campaign dates, a
source-credibility tag); it can never alter pipeline config, rulesets,
scope, or tier.

Attaching intel creates a new **revision**, not a silent model mutation:
it inherits the parent's system model, pins the same KB/CRI snapshots
(so any change is attributable to intel alone), can raise likelihood on
techniques it corroborates, can add intel-derived candidate threats
(subject to the identical grounding gate as everything else — an
intel-only claim with no real ATT&CK/ATLAS backing never becomes a
finding), and can re-open adjudications whose own stated
`invalidation_condition` the intel satisfies. Every revision diffs
cleanly against its parent (`GET /projects/{id}/revisions/{id}/diff`).

## Security

This build defaults to the exact behavior a purely local, single-operator
tool needs — no auth, no rate limit, docs enabled — and every hardening
control below is opt-in via one environment variable, so turning nothing
on preserves that default exactly. Before running it anywhere reachable
by anyone but you, turn these on:

1. **Set `TM_API_KEY`** to require a matching `X-API-Key` header on every
   request (`app/api/auth.py::require_api_key`, wired once as a global
   FastAPI dependency so no router can be missed). The comparison uses
   `hmac.compare_digest`, so response timing can't leak how many leading
   characters of a guess were correct. As soon as it's set, the
   interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are disabled
   outright rather than left reachable without a key
   (`app/main.py::create_app`) — those are plain framework routes that a
   dependency can't gate, so the safer answer is to turn them off.
2. **Set `TM_RATE_LIMIT_PER_MINUTE`** to cap requests per client IP on the
   endpoints that actually invoke an LLM (report/export generation,
   review-item generation, revision creation) — a minimal in-memory
   sliding-window limiter (`app/api/rate_limit.py`), since each of those
   calls has a real dollar cost.
3. **Put a reverse proxy in front of it anyway if you can.** The server
   itself still refuses to bind beyond loopback at all unless you pass
   `--allow-non-loopback` (or `TM_ALLOW_NON_LOOPBACK=true`), and doing so
   logs a warning if `TM_API_KEY` isn't also set
   (`app/core/config.py::assert_bind_allowed`).
4. **CORS is a strict allowlist**, not a wildcard
   (`TM_CORS_ALLOWED_ORIGINS`) — add your real frontend origin, don't
   open it up broadly.
5. **Upload limits are enforced** on every upload endpoint (design
   documents, CRI workbooks) via `TM_MAX_UPLOAD_BYTES`, checked
   incrementally while the body streams in rather than after buffering it
   whole (`app/services/upload_validation.py::read_upload_within_limit`).
   DOCX/XLSX uploads are additionally checked for anomalous
   compression ratios and uncompressed size before being handed to the
   parsing library, to reject zip-bomb payloads
   (`app/services/zip_bomb_guard.py`).
6. **Every request body has a size ceiling, not just file uploads.**
   `TM_MAX_REQUEST_BODY_BYTES` is enforced by ASGI middleware
   (`app/api/body_size_limit.py::BodySizeLimitMiddleware`) in front of
   every endpoint: a well-behaved client's declared `Content-Length` is
   checked before a single byte is read, and a chunked body with no
   `Content-Length` is bounded by tracking the running total and aborting
   the read the instant it crosses the limit — a plain JSON body (e.g. an
   oversized list field) can't be used to force the server to fully
   buffer and parse an arbitrarily large payload.
7. **All locally stored data is owner-only on disk.** Every directory and
   file this platform creates — uploaded documents, KB/CRI/intel
   snapshots, the SQLite database, the LLM completion cache, per-run
   artifacts — is created at `0700`/`0600` regardless of the process
   umask (`app/services/fs_permissions.py`), since filesystem permissions
   are the only boundary between this data and another local account when
   there's no in-app multi-user isolation.
8. **Secrets are redacted before they ever reach an LLM provider.**
   `app/services/llm/redaction.py` scans for common secret shapes
   (provider API keys, AWS keys, PEM private key blocks, JWTs, generic
   `password:`/`token:` assignments) and the real gateway dependency
   (`app/api/deps.py::get_llm_gateway`) has this on by default — a
   secret accidentally pasted into an uploaded design document is
   redacted before the prompt is ever sent or logged. The audit log
   applies the same redaction, recursively through nested dicts/lists, to
   every summary/detail field it stores.
9. **API keys are never stored in the database, logs, or exports** —
   resolved from an environment variable or the OS keyring at call time
   only (`app/services/llm/keys.py`), and no error message or log line
   in this codebase ever includes a resolved key value.
10. **Outbound intel fetches are SSRF-hardened against DNS rebinding**: the
    IP a hostname resolves to is validated and then pinned for the actual
    connection, closing the gap between the resolve-time check and
    connect-time DNS lookup (`app/services/intel/ssrf_guard.py`).
11. **Content-addressed lookups validate their hash format** before it
    ever reaches a filesystem path join, so a malformed or path-traversal
    value 404s instead of reaching `os.path`
    (`app/services/content_addressing.py`).

## Audit log

`GET /audit-log` (global) and `GET /projects/{id}/audit-log`
(project-scoped) expose an append-only log
(`app/models/audit.py` + `app/services/audit/service.py` — the service
exposes only `record` and `list_entries`, nothing that can rewrite
history) covering KB and CRI refreshes, tiering answers, intel
ingestion, model freezes and manual edits, every report/export
generated, and every agent invocation (agent name, tool-call count,
cache-hit, and wall-clock latency). Review-item decisions additionally
have their own dedicated, per-item append-only trail
(`GET /projects/{id}/review-items/{id}/audit`) alongside a `review.decided`
entry on this general log.

**Known limitation, documented rather than glossed over:** per-invocation
LLM cost and token usage are not currently captured in the audit log or
in structured logs. `TrajectoryRecord`/`ToolCallRecord`
(`app/orchestrator/contracts.py`) record tool calls and their return
values, but an agent's tool functions currently return only the
extracted domain value (e.g. a drafted recommendation), not the LLM
gateway's own `GatewayResult` (which does carry cost and token usage) —
that plumbing would need to be threaded through every agent's tool
functions to expose cost/latency-per-dollar views, and hasn't been done.
Wall-clock latency and tool-call count *are* captured, both in the audit
log and via structured `INFO`-level logging emitted directly by the
Orchestrator on every invocation (`app/orchestrator/orchestrator.py`).

## Backup and restore

```bash
python -m app.services.backup create ./backup-2026-07-29.tar.gz
python -m app.services.backup restore ./backup-2026-07-29.tar.gz
```

The archive contains `data_dir` (KB/CRI/intel snapshots, uploaded
project documents) and the SQLite database file (runs, revisions, review
items, audit log — everything else this app persists), since restoring
only one half would not reproduce prior runs, revisions, or scores.
Restore extracts with Python's `tarfile` `"data"` filter, so no archive
member can escape the intended destination via a path-traversal name.
Stop the server before restoring — this is a local, single-tenant v1
app; there is no online/point-in-time restore story.

## Testing

Every task in `IMPLEMENTATION_PLAN.md` documents its own real test count
and a real demo — including, where LLM credentials aren't available in a
given environment, an explicit note of which endpoints were verified
live via curl (usually confirming an honest `503`) versus verified
end-to-end through the real HTTP/DB stack with a deterministic
`FakeProvider` standing in for the real LLM. `FakeProvider`
(`app/services/llm/fake_provider.py`) never calls a network; it exists
specifically so the whole pipeline's correctness can be exercised
without live credentials, while still going through every real
service/DB/orchestrator code path.
