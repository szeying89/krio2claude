"""Merge Mermaid-derived structure with LLM-derived prose extraction.

Precedence (IMPLEMENTATION_PLAN.md, Task 8): Mermaid structure is
authoritative — it is never overwritten by prose. Prose supplies
attributes (technology tags, protocols, classifications, control
mappings) onto matching elements and contributes elements the diagram
never drew at all. Every attribute conflict, every prose-only addition,
and every defaulted field is recorded as a typed `Assumption` so nothing
enters the draft model silently.

Entity resolution across both sources — and across every document in a
project, so the same component drawn in one file and only described in
another still becomes one element — is by case-insensitive,
whitespace-collapsed name matching. This is a deliberately simple,
deterministic heuristic (same spirit as
`app/services/kb/heuristic_mapping.py`): it will under-merge synonyms
("auth svc" vs "Authentication Service") and over-merge unrelated same-
named elements in different documents, both acceptable given everything
it does is visible in the assumption ledger, not silently assumed correct.
"""

from __future__ import annotations

import re

from app.services.mermaid.models import NodeShape, ParsedDiagram
from app.services.modelbuilding.models import (
    Assumption,
    DeclaredControl,
    ModelActor,
    ModelAsset,
    ModelComponent,
    ModelFlow,
    ModelTrustZone,
    SourceSpan,
    SystemModelDraft,
)
from app.services.modelbuilding.prose_extractor import (
    ProseAsset,
    ProseDeclaredControl,
    ProseExtractionResult,
    ProseFlow,
    ProseTrustZone,
)

_DATASTORE_SHAPES = {NodeShape.CYLINDER}
_ACTOR_SHAPES = {NodeShape.CIRCLE, NodeShape.DOUBLE_CIRCLE, NodeShape.STADIUM}


def normalize_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "item"


def infer_kind_from_shape(shape: NodeShape) -> str:
    """Heuristic DFD-shape convention (cylinder -> data store, circle or
    stadium -> external actor, everything else -> process) — not
    authoritative, just a documented starting guess prose can supplement."""
    if shape in _DATASTORE_SHAPES:
        return "datastore"
    if shape in _ACTOR_SHAPES:
        return "external_entity"
    return "process"


class ModelBuilder:
    """Accumulates a SystemModelDraft across any number of documents, each
    contributing an (optional) list of parsed Mermaid diagrams and an
    (optional) prose extraction result."""

    def __init__(self) -> None:
        self.draft = SystemModelDraft()
        self._name_to_id: dict[str, str] = {}
        self._node_to_id: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def _next_id(self, prefix: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}-{n}"

    # --- Mermaid ingestion -------------------------------------------------

    def add_diagram(self, document_id: str, diagram: ParsedDiagram) -> None:
        for node in diagram.nodes:
            self._add_mermaid_node(document_id, node.id, node.label or node.id, node.shape, node.line)

        for edge in diagram.edges:
            source_id = self._node_to_id.get((document_id, edge.source))
            target_id = self._node_to_id.get((document_id, edge.target))
            if source_id is None:
                source_id = self._add_mermaid_node(
                    document_id, edge.source, edge.source, NodeShape.DEFAULT, edge.line
                )
            if target_id is None:
                target_id = self._add_mermaid_node(
                    document_id, edge.target, edge.target, NodeShape.DEFAULT, edge.line
                )
            self.draft.flows.append(
                ModelFlow(
                    id=self._next_id("flow"),
                    source_id=source_id,
                    target_id=target_id,
                    label=edge.label or "",
                    protocol=None,
                    authenticated=None,
                    encrypted=None,
                    source="mermaid",
                    source_spans=(SourceSpan(document_id, edge.line, edge.line),),
                )
            )

        for subgraph in diagram.subgraphs:
            member_ids = tuple(
                self._node_to_id[(document_id, node_id)]
                for node_id in subgraph.node_ids
                if (document_id, node_id) in self._node_to_id
            )
            zone_id = self._next_id("trust-zone")
            self.draft.trust_zones.append(
                ModelTrustZone(
                    id=zone_id,
                    name=subgraph.title or subgraph.id,
                    member_ids=member_ids,
                    source="mermaid",
                    source_spans=(SourceSpan(document_id, subgraph.line, subgraph.line),),
                )
            )
            for member_id in member_ids:
                component = next(
                    (c for c in self.draft.components if c.id == member_id), None
                )
                if component is not None and component.trust_zone_id is None:
                    component.trust_zone_id = zone_id

    def _add_mermaid_node(
        self, document_id: str, node_id: str, label: str, shape: NodeShape, line: int
    ) -> str:
        key = (document_id, node_id)
        if key in self._node_to_id:
            return self._node_to_id[key]

        normalized = normalize_name(label)
        existing_id = self._name_to_id.get(normalized)
        if existing_id is not None:
            self._node_to_id[key] = existing_id
            return existing_id

        kind = infer_kind_from_shape(shape)
        span = SourceSpan(document_id, line, line)
        if kind == "external_entity":
            element_id = self._next_id("actor")
            self.draft.actors.append(
                ModelActor(
                    id=element_id,
                    name=label,
                    kind=kind,
                    source="mermaid",
                    source_spans=(span,),
                )
            )
        else:
            element_id = self._next_id("component")
            self.draft.components.append(
                ModelComponent(
                    id=element_id,
                    name=label,
                    kind=kind,
                    trust_zone_id=None,
                    technology_tags=(),
                    source="mermaid",
                    source_spans=(span,),
                )
            )
        self._node_to_id[key] = element_id
        self._name_to_id[normalized] = element_id
        return element_id

    # --- Prose ingestion -----------------------------------------------

    def add_prose_extraction(self, document_id: str, extraction: ProseExtractionResult) -> None:
        for component in extraction.components:
            self._merge_component_or_actor(
                document_id=document_id,
                name=component.name,
                kind=component.kind if component.kind in ("process", "datastore") else "process",
                technology_tags=tuple(component.technology_tags),
                confidence=component.confidence,
                start_line=component.source_span.start_line,
                end_line=component.source_span.end_line,
            )
        for actor in extraction.actors:
            self._merge_component_or_actor(
                document_id=document_id,
                name=actor.name,
                kind="external_entity",
                technology_tags=(),
                confidence=actor.confidence,
                start_line=actor.source_span.start_line,
                end_line=actor.source_span.end_line,
            )
        for flow in extraction.flows:
            self._merge_flow(document_id, flow)
        for asset in extraction.assets:
            self._merge_asset(document_id, asset)
        for trust_zone in extraction.trust_zones:
            self._merge_trust_zone(document_id, trust_zone)
        for control in extraction.declared_controls:
            self._merge_declared_control(document_id, control)

    def _merge_component_or_actor(
        self,
        document_id: str,
        name: str,
        kind: str,
        technology_tags: tuple[str, ...],
        confidence: float,
        start_line: int,
        end_line: int,
    ) -> str:
        normalized = normalize_name(name)
        span = SourceSpan(document_id, start_line, end_line)
        existing_id = self._name_to_id.get(normalized)

        if existing_id is None:
            element_id = self._next_id("actor" if kind == "external_entity" else "component")
            if kind == "external_entity":
                self.draft.actors.append(
                    ModelActor(
                        id=element_id, name=name, kind=kind, source="prose", source_spans=(span,)
                    )
                )
            else:
                self.draft.components.append(
                    ModelComponent(
                        id=element_id,
                        name=name,
                        kind=kind,
                        trust_zone_id=None,
                        technology_tags=technology_tags,
                        source="prose",
                        source_spans=(span,),
                    )
                )
            self._name_to_id[normalized] = element_id
            self.draft.assumptions.append(
                Assumption(
                    kind="inference",
                    subject_id=element_id,
                    message=f"{name!r} appears only in prose, not in any diagram",
                    source="prose",
                    confidence=confidence,
                    impact_if_wrong="an element enumeration/threat assessment covers may not "
                    "actually exist as described",
                )
            )
            return element_id

        component = next((c for c in self.draft.components if c.id == existing_id), None)
        if component is not None:
            component.source_spans = component.source_spans + (span,)
            if component.kind != kind:
                self.draft.assumptions.append(
                    Assumption(
                        kind="conflict",
                        subject_id=existing_id,
                        message=(
                            f"prose describes {name!r} as {kind!r} but the diagram shape "
                            f"implies {component.kind!r}; keeping the diagram's reading"
                        ),
                        source="merge",
                        confidence=confidence,
                        impact_if_wrong="element may be mis-classified for STRIDE purposes",
                    )
                )
            if technology_tags:
                merged_tags = tuple(dict.fromkeys(component.technology_tags + technology_tags))
                component.technology_tags = merged_tags
            component.source = "merged"
        else:
            actor = next((a for a in self.draft.actors if a.id == existing_id), None)
            if actor is not None:
                actor.source_spans = actor.source_spans + (span,)
                actor.source = "merged"
        return existing_id

    def _resolve_or_stub(self, document_id: str, name: str, confidence: float) -> str:
        """Resolve a name to a known element, or create a bare (no shape
        evidence) component stub for it — used when a prose flow/control
        references something not independently declared as a component or
        actor. The stub itself is logged as an inference."""
        existing_id = self._name_to_id.get(normalize_name(name))
        if existing_id is not None:
            return existing_id
        return self._merge_component_or_actor(
            document_id=document_id,
            name=name,
            kind="process",
            technology_tags=(),
            confidence=confidence,
            start_line=1,
            end_line=1,
        )

    def _merge_flow(self, document_id: str, item: ProseFlow) -> None:
        source_id = self._resolve_or_stub(document_id, item.source_name, item.confidence)
        target_id = self._resolve_or_stub(document_id, item.target_name, item.confidence)

        existing = next(
            (
                f
                for f in self.draft.flows
                if f.source_id == source_id and f.target_id == target_id
            ),
            None,
        )
        span = SourceSpan(document_id, item.source_span.start_line, item.source_span.end_line)
        if existing is None:
            self.draft.flows.append(
                ModelFlow(
                    id=self._next_id("flow"),
                    source_id=source_id,
                    target_id=target_id,
                    label=item.label,
                    protocol=item.protocol,
                    authenticated=item.authenticated,
                    encrypted=item.encrypted,
                    source="prose",
                    source_spans=(span,),
                )
            )
            self.draft.assumptions.append(
                Assumption(
                    kind="inference",
                    subject_id=source_id,
                    message=f"flow {item.source_name!r} -> {item.target_name!r} appears only in prose",
                    source="prose",
                    confidence=item.confidence,
                    impact_if_wrong="a data flow enumeration may cover a path that doesn't exist",
                )
            )
            return

        existing.source_spans = existing.source_spans + (span,)
        for field_name, new_value in (
            ("protocol", item.protocol),
            ("authenticated", item.authenticated),
            ("encrypted", item.encrypted),
        ):
            if new_value is None:
                continue
            current = getattr(existing, field_name)
            if current is None:
                setattr(existing, field_name, new_value)
            elif current != new_value:
                self.draft.assumptions.append(
                    Assumption(
                        kind="conflict",
                        subject_id=existing.id,
                        message=(
                            f"prose states {field_name}={new_value!r} for flow "
                            f"{item.source_name!r} -> {item.target_name!r}, diagram/prior "
                            f"text implied {current!r}; keeping the earlier value"
                        ),
                        source="merge",
                        confidence=item.confidence,
                        impact_if_wrong="a boundary-crossing control property may be wrong",
                    )
                )
        existing.source = "merged"

    def _merge_asset(self, document_id: str, item: ProseAsset) -> None:
        classification = item.classification
        span = SourceSpan(document_id, item.source_span.start_line, item.source_span.end_line)
        asset_id = self._slug_asset_id(item.name)
        if not classification or not classification.strip():
            classification = "unclassified"
            self.draft.assumptions.append(
                Assumption(
                    kind="default",
                    subject_id=asset_id,
                    message=f"asset {item.name!r} has no stated data classification; defaulted "
                    "to 'unclassified'",
                    source="prose",
                    confidence=item.confidence,
                    impact_if_wrong="an asset may be under- or over-protected relative to its "
                    "real sensitivity",
                )
            )
        owner_id = (
            self._name_to_id.get(normalize_name(item.owner_name)) if item.owner_name else None
        )
        self.draft.assets.append(
            ModelAsset(
                id=asset_id,
                name=item.name,
                classification=classification,
                owner_id=owner_id,
                source="prose",
                source_spans=(span,),
            )
        )
        self.draft.assumptions.append(
            Assumption(
                kind="inference",
                subject_id=asset_id,
                message=f"asset {item.name!r} is described only in prose",
                source="prose",
                confidence=item.confidence,
                impact_if_wrong="an asset the design doesn't actually handle may be assessed",
            )
        )

    def _slug_asset_id(self, name: str) -> str:
        return self._next_id(f"asset-{_slug(name)}")

    def _merge_trust_zone(self, document_id: str, item: ProseTrustZone) -> None:
        normalized = normalize_name(item.name)
        existing = next(
            (z for z in self.draft.trust_zones if normalize_name(z.name) == normalized), None
        )
        span = SourceSpan(document_id, item.source_span.start_line, item.source_span.end_line)
        member_ids = tuple(
            self._name_to_id[normalize_name(member)]
            for member in item.member_names
            if normalize_name(member) in self._name_to_id
        )
        if existing is not None:
            existing.member_ids = tuple(dict.fromkeys(existing.member_ids + member_ids))
            existing.source_spans = existing.source_spans + (span,)
            existing.source = "merged"
            return

        zone_id = self._next_id("trust-zone")
        self.draft.trust_zones.append(
            ModelTrustZone(
                id=zone_id,
                name=item.name,
                member_ids=member_ids,
                source="prose",
                source_spans=(span,),
            )
        )
        self.draft.assumptions.append(
            Assumption(
                kind="inference",
                subject_id=zone_id,
                message=f"trust zone {item.name!r} appears only in prose, not in any diagram",
                source="prose",
                confidence=item.confidence,
                impact_if_wrong="a boundary crossing may be miscounted or missed entirely",
            )
        )
        for member_id in member_ids:
            component = next((c for c in self.draft.components if c.id == member_id), None)
            if component is not None and component.trust_zone_id is None:
                component.trust_zone_id = zone_id

    def _merge_declared_control(self, document_id: str, item: ProseDeclaredControl) -> None:
        span = SourceSpan(document_id, item.source_span.start_line, item.source_span.end_line)
        applies_to_ids = tuple(
            self._name_to_id[normalize_name(target)]
            for target in item.applies_to_names
            if normalize_name(target) in self._name_to_id
        )
        control_id = self._next_id(f"control-{_slug(item.name)}")
        self.draft.declared_controls.append(
            DeclaredControl(
                id=control_id,
                name=item.name,
                applies_to_ids=applies_to_ids,
                source="prose",
                source_spans=(span,),
            )
        )

    def element_trust_zone(self, element_id: str) -> str | None:
        for zone in self.draft.trust_zones:
            if element_id in zone.member_ids:
                return zone.id
        return None
