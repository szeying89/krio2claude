"""The canonical `SystemModel` (IMPLEMENTATION_PLAN.md, Task 9): an OTM
0.2.0 superset. Every entity maps cleanly onto its OTM counterpart
(trustZone/component/dataflow/asset) for `to_otm`/`from_otm` round-tripping
in `otm.py`; fields the base OTM spec has no place for (technology tags,
protocol/auth/encryption, our classification string, out-of-scope
declarations, and — the reason this needs its own model at all instead of
just reusing Task 8's `SystemModelDraft` — per-element `provenance` and
per-version `change_summary`) live in this model and get folded into OTM's
own `attributes` object on export, not lost.

`provenance` distinguishes what the Model-Building Agent produced
(`"agent_generated"`) from what a human has since edited
(`"user_asserted"`) — the plan requires user edits to "version the model
with user_asserted provenance", which is a per-element fact (only the
elements someone actually touched change provenance), not a per-model one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

Provenance = str  # "agent_generated" | "user_asserted"


@dataclass
class TrustZone:
    id: str
    name: str
    trust_rating: int
    description: str | None = None
    provenance: Provenance = "agent_generated"


@dataclass
class Component:
    id: str
    name: str
    kind: str  # "process" | "datastore" | "external_entity"
    trust_zone_id: str
    technology_tags: tuple[str, ...] = ()
    description: str | None = None
    provenance: Provenance = "agent_generated"
    out_of_scope: bool = False
    out_of_scope_reason: str | None = None


@dataclass
class Dataflow:
    id: str
    name: str
    source_id: str
    destination_id: str
    bidirectional: bool = False
    protocol: str | None = None
    authenticated: bool | None = None
    encrypted: bool | None = None
    provenance: Provenance = "agent_generated"


@dataclass
class Asset:
    id: str
    name: str
    classification: str | None
    confidentiality: int
    integrity: int
    availability: int
    owner_id: str | None = None
    provenance: Provenance = "agent_generated"


@dataclass
class OutOfScopeDeclaration:
    id: str
    subject_id: str
    category: str  # "ot_ics" | "mobile_client"
    indicator: str
    reason: str


@dataclass
class DeclaredControl:
    id: str
    name: str
    applies_to_ids: tuple[str, ...] = ()
    provenance: Provenance = "agent_generated"


@dataclass
class SystemModel:
    id: str
    version: int
    parent_version: int | None
    trust_zones: list[TrustZone] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    dataflows: list[Dataflow] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    out_of_scope: list[OutOfScopeDeclaration] = field(default_factory=list)
    declared_controls: list[DeclaredControl] = field(default_factory=list)
    change_summary: list[str] = field(default_factory=list)
    created_at: datetime | None = None
