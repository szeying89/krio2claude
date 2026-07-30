"""User edits onto a `SystemModel`: the plan requires edits to "version
the model with user_asserted provenance" — `apply_edits` never mutates the
model it's given (each version is immutable once frozen); it deep-copies,
applies only the fields the caller actually sent, flips `provenance` to
`"user_asserted"` on exactly the entities touched, and returns a new
in-memory model for the caller to persist as the next version.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from app.services.systemmodel.models import SystemModel


class UnknownElementError(Exception):
    pass


@dataclass
class ComponentEdit:
    id: str
    name: str | None = None
    kind: str | None = None
    technology_tags: list[str] | None = None
    trust_zone_id: str | None = None
    description: str | None = None


@dataclass
class DataflowEdit:
    id: str
    name: str | None = None
    protocol: str | None = None
    authenticated: bool | None = None
    encrypted: bool | None = None


@dataclass
class AssetEdit:
    id: str
    classification: str | None = None


@dataclass
class TrustZoneEdit:
    id: str
    name: str | None = None
    trust_rating: int | None = None


@dataclass
class ModelEdits:
    components: list[ComponentEdit] = field(default_factory=list)
    dataflows: list[DataflowEdit] = field(default_factory=list)
    assets: list[AssetEdit] = field(default_factory=list)
    trust_zones: list[TrustZoneEdit] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.components or self.dataflows or self.assets or self.trust_zones)


def apply_edits(model: SystemModel, edits: ModelEdits) -> SystemModel:
    updated = copy.deepcopy(model)

    components_by_id = {c.id: c for c in updated.components}
    for component_edit in edits.components:
        component = components_by_id.get(component_edit.id)
        if component is None:
            raise UnknownElementError(f"no component with id {component_edit.id!r}")
        if component_edit.name is not None:
            component.name = component_edit.name
        if component_edit.kind is not None:
            component.kind = component_edit.kind
        if component_edit.technology_tags is not None:
            component.technology_tags = tuple(component_edit.technology_tags)
        if component_edit.trust_zone_id is not None:
            component.trust_zone_id = component_edit.trust_zone_id
        if component_edit.description is not None:
            component.description = component_edit.description
        component.provenance = "user_asserted"

    dataflows_by_id = {f.id: f for f in updated.dataflows}
    for flow_edit in edits.dataflows:
        flow = dataflows_by_id.get(flow_edit.id)
        if flow is None:
            raise UnknownElementError(f"no dataflow with id {flow_edit.id!r}")
        if flow_edit.name is not None:
            flow.name = flow_edit.name
        if flow_edit.protocol is not None:
            flow.protocol = flow_edit.protocol
        if flow_edit.authenticated is not None:
            flow.authenticated = flow_edit.authenticated
        if flow_edit.encrypted is not None:
            flow.encrypted = flow_edit.encrypted
        flow.provenance = "user_asserted"

    assets_by_id = {a.id: a for a in updated.assets}
    for asset_edit in edits.assets:
        asset = assets_by_id.get(asset_edit.id)
        if asset is None:
            raise UnknownElementError(f"no asset with id {asset_edit.id!r}")
        if asset_edit.classification is not None:
            asset.classification = asset_edit.classification
        asset.provenance = "user_asserted"

    trust_zones_by_id = {z.id: z for z in updated.trust_zones}
    for zone_edit in edits.trust_zones:
        zone = trust_zones_by_id.get(zone_edit.id)
        if zone is None:
            raise UnknownElementError(f"no trust zone with id {zone_edit.id!r}")
        if zone_edit.name is not None:
            zone.name = zone_edit.name
        if zone_edit.trust_rating is not None:
            zone.trust_rating = zone_edit.trust_rating
        zone.provenance = "user_asserted"

    return updated
