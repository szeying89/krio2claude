"""Shared data model for the Model-Building Agent's draft system model.

This is a *draft*, not the frozen `SystemModel` (Task 9's OTM-0.2.0
superset) — it exists so Mermaid-derived structure and LLM-derived prose
extraction can be merged, every conflict/inference/default recorded as a
typed Assumption, and every dangling reference caught by the completeness
gate, all before Task 9 commits to a canonical, versioned representation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ElementKind = str  # "process" | "datastore" | "external_entity"
AssumptionKind = str  # "conflict" | "inference" | "default"
FindingKind = str  # "dangling_flow" | "sourceless_sink" | "unclassified_asset" | "untagged_boundary_crossing"
Provenance = str  # "mermaid" | "prose" | "merged"


@dataclass(frozen=True)
class SourceSpan:
    """A citation into either a Mermaid block's own source text or a
    document's extracted-prose text. `document_id` disambiguates which
    document (and, implicitly, which coordinate space) the line numbers
    are relative to — Mermaid line numbers are relative to that block's
    own source text, prose line numbers are relative to the document's
    `extracted_prose` (mermaid fences already stripped), never the
    original uploaded file."""

    document_id: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class Assumption:
    kind: AssumptionKind
    subject_id: str
    message: str
    source: Provenance
    confidence: float
    impact_if_wrong: str


@dataclass(frozen=True)
class CompletenessFinding:
    kind: FindingKind
    subject_id: str
    message: str


@dataclass
class ModelComponent:
    id: str
    name: str
    kind: ElementKind
    trust_zone_id: str | None
    technology_tags: tuple[str, ...]
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class ModelActor:
    id: str
    name: str
    kind: ElementKind  # "external_entity", always
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class ModelFlow:
    id: str
    source_id: str
    target_id: str
    label: str
    protocol: str | None
    authenticated: bool | None
    encrypted: bool | None
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class ModelAsset:
    id: str
    name: str
    classification: str | None
    owner_id: str | None
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class ModelTrustZone:
    id: str
    name: str
    member_ids: tuple[str, ...]
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class DeclaredControl:
    id: str
    name: str
    applies_to_ids: tuple[str, ...]
    source: Provenance
    source_spans: tuple[SourceSpan, ...]


@dataclass
class SystemModelDraft:
    components: list[ModelComponent] = field(default_factory=list)
    actors: list[ModelActor] = field(default_factory=list)
    flows: list[ModelFlow] = field(default_factory=list)
    assets: list[ModelAsset] = field(default_factory=list)
    trust_zones: list[ModelTrustZone] = field(default_factory=list)
    declared_controls: list[DeclaredControl] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    completeness_findings: list[CompletenessFinding] = field(default_factory=list)

    @property
    def needs_input(self) -> bool:
        return len(self.completeness_findings) > 0
