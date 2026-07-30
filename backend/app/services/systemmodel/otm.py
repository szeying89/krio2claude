"""OTM 0.2.0 conversion — `SystemModel` is a superset of OTM, so `to_otm`
produces a document any generic OTM consumer can read (standard
`project`/`trustZones`/`components`/`dataflows`/`assets` fields), while
every platform-specific extension (technology tags, protocol/auth/
encryption, our classification string, provenance, out-of-scope
declarations, version/change-summary metadata) round-trips losslessly
through each entity's OTM-native `attributes` object, namespaced under
`tm_platform` so it never collides with a real OTM consumer's own
attributes.

`from_otm(to_otm(model))` must reproduce `model` exactly — that's the
"model -> OTM -> model round-trips semantically" test requirement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.services.systemmodel.models import (
    Asset,
    Component,
    Dataflow,
    DeclaredControl,
    OutOfScopeDeclaration,
    SystemModel,
    TrustZone,
)

OTM_VERSION = "0.2.0"


def to_otm(model: SystemModel) -> dict[str, Any]:
    return {
        "otmVersion": OTM_VERSION,
        "project": {
            "id": model.id,
            "name": f"System Model {model.id} v{model.version}",
            "attributes": {
                "tm_platform": {
                    "version": model.version,
                    "parent_version": model.parent_version,
                    "change_summary": list(model.change_summary),
                    "out_of_scope": [_out_of_scope_to_otm(o) for o in model.out_of_scope],
                    "created_at": model.created_at.isoformat() if model.created_at else None,
                }
            },
        },
        "trustZones": [_trust_zone_to_otm(z) for z in model.trust_zones],
        "components": [_component_to_otm(c) for c in model.components],
        "dataflows": [_dataflow_to_otm(f) for f in model.dataflows],
        "assets": [_asset_to_otm(a) for a in model.assets],
        "mitigations": [_declared_control_to_otm(c) for c in model.declared_controls],
    }


def _trust_zone_to_otm(zone: TrustZone) -> dict[str, Any]:
    return {
        "id": zone.id,
        "name": zone.name,
        "risk": {"trustRating": zone.trust_rating},
        "description": zone.description,
        "attributes": {"tm_platform": {"provenance": zone.provenance}},
    }


def _component_to_otm(component: Component) -> dict[str, Any]:
    return {
        "id": component.id,
        "name": component.name,
        "type": component.kind,
        "parent": {"trustZone": component.trust_zone_id},
        "description": component.description,
        "attributes": {
            "tm_platform": {
                "technology_tags": list(component.technology_tags),
                "provenance": component.provenance,
                "out_of_scope": component.out_of_scope,
                "out_of_scope_reason": component.out_of_scope_reason,
            }
        },
    }


def _dataflow_to_otm(flow: Dataflow) -> dict[str, Any]:
    return {
        "id": flow.id,
        "name": flow.name,
        "source": flow.source_id,
        "destination": flow.destination_id,
        "bidirectional": flow.bidirectional,
        "attributes": {
            "tm_platform": {
                "protocol": flow.protocol,
                "authenticated": flow.authenticated,
                "encrypted": flow.encrypted,
                "provenance": flow.provenance,
            }
        },
    }


def _asset_to_otm(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "name": asset.name,
        "risk": {
            "confidentiality": asset.confidentiality,
            "integrity": asset.integrity,
            "availability": asset.availability,
        },
        "attributes": {
            "tm_platform": {
                "classification": asset.classification,
                "owner_id": asset.owner_id,
                "provenance": asset.provenance,
            }
        },
    }


def _declared_control_to_otm(control: DeclaredControl) -> dict[str, Any]:
    """Maps onto OTM's native `mitigation` object — a reasonable semantic
    fit for "a declared control" — with `riskReduction` defaulted to 0
    (undetermined; this platform doesn't compute a risk-reduction
    percentage) and `applies_to_ids`/`provenance` carried in `attributes`
    since OTM expresses control-to-threat linkage at the per-threat level,
    which this model doesn't track that granularly."""
    return {
        "id": control.id,
        "name": control.name,
        "riskReduction": 0,
        "attributes": {
            "tm_platform": {
                "applies_to_ids": list(control.applies_to_ids),
                "provenance": control.provenance,
            }
        },
    }


def _out_of_scope_to_otm(declaration: OutOfScopeDeclaration) -> dict[str, Any]:
    return {
        "id": declaration.id,
        "subject_id": declaration.subject_id,
        "category": declaration.category,
        "indicator": declaration.indicator,
        "reason": declaration.reason,
    }


def _tm_attrs(entity: dict[str, Any]) -> dict[str, Any]:
    attrs: dict[str, Any] = entity.get("attributes") or {}
    result: dict[str, Any] = attrs.get("tm_platform") or {}
    return result


def from_otm(otm: dict[str, Any]) -> SystemModel:
    project = otm["project"]
    project_attrs = _tm_attrs(project)

    trust_zones = [_trust_zone_from_otm(z) for z in otm.get("trustZones", [])]
    components = [_component_from_otm(c) for c in otm.get("components", [])]
    dataflows = [_dataflow_from_otm(f) for f in otm.get("dataflows", [])]
    assets = [_asset_from_otm(a) for a in otm.get("assets", [])]
    declared_controls = [_declared_control_from_otm(m) for m in otm.get("mitigations", [])]
    out_of_scope = [
        OutOfScopeDeclaration(
            id=o["id"],
            subject_id=o["subject_id"],
            category=o["category"],
            indicator=o["indicator"],
            reason=o["reason"],
        )
        for o in project_attrs.get("out_of_scope", [])
    ]

    created_at_raw = project_attrs.get("created_at")
    return SystemModel(
        id=project["id"],
        version=project_attrs["version"],
        parent_version=project_attrs.get("parent_version"),
        trust_zones=trust_zones,
        components=components,
        dataflows=dataflows,
        assets=assets,
        out_of_scope=out_of_scope,
        declared_controls=declared_controls,
        change_summary=list(project_attrs.get("change_summary", [])),
        created_at=datetime.fromisoformat(created_at_raw) if created_at_raw else None,
    )


def _trust_zone_from_otm(otm_zone: dict[str, Any]) -> TrustZone:
    attrs = _tm_attrs(otm_zone)
    return TrustZone(
        id=otm_zone["id"],
        name=otm_zone["name"],
        trust_rating=otm_zone["risk"]["trustRating"],
        description=otm_zone.get("description"),
        provenance=attrs.get("provenance", "agent_generated"),
    )


def _component_from_otm(otm_component: dict[str, Any]) -> Component:
    attrs = _tm_attrs(otm_component)
    return Component(
        id=otm_component["id"],
        name=otm_component["name"],
        kind=otm_component["type"],
        trust_zone_id=otm_component["parent"]["trustZone"],
        technology_tags=tuple(attrs.get("technology_tags", [])),
        description=otm_component.get("description"),
        provenance=attrs.get("provenance", "agent_generated"),
        out_of_scope=attrs.get("out_of_scope", False),
        out_of_scope_reason=attrs.get("out_of_scope_reason"),
    )


def _dataflow_from_otm(otm_flow: dict[str, Any]) -> Dataflow:
    attrs = _tm_attrs(otm_flow)
    return Dataflow(
        id=otm_flow["id"],
        name=otm_flow["name"],
        source_id=otm_flow["source"],
        destination_id=otm_flow["destination"],
        bidirectional=otm_flow.get("bidirectional", False),
        protocol=attrs.get("protocol"),
        authenticated=attrs.get("authenticated"),
        encrypted=attrs.get("encrypted"),
        provenance=attrs.get("provenance", "agent_generated"),
    )


def _declared_control_from_otm(otm_mitigation: dict[str, Any]) -> DeclaredControl:
    attrs = _tm_attrs(otm_mitigation)
    return DeclaredControl(
        id=otm_mitigation["id"],
        name=otm_mitigation["name"],
        applies_to_ids=tuple(attrs.get("applies_to_ids", [])),
        provenance=attrs.get("provenance", "agent_generated"),
    )


def _asset_from_otm(otm_asset: dict[str, Any]) -> Asset:
    attrs = _tm_attrs(otm_asset)
    risk = otm_asset["risk"]
    return Asset(
        id=otm_asset["id"],
        name=otm_asset["name"],
        classification=attrs.get("classification"),
        confidentiality=risk["confidentiality"],
        integrity=risk["integrity"],
        availability=risk["availability"],
        owner_id=attrs.get("owner_id"),
        provenance=attrs.get("provenance", "agent_generated"),
    )
