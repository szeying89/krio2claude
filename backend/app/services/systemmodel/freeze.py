"""Freeze a Task 8 `SystemModelDraft` into the canonical `SystemModel`.

OTM requires every component to have a parent (trust zone or component);
Task 8's draft allows unzoned components (nothing in the source material
put them in a boundary). Rather than silently dropping that information or
producing invalid OTM, every unzoned element is assigned to an
auto-created "Unclassified Zone" and the assignment is recorded in
`change_summary` — visible, not silent, same as every other default in
this plan.
"""

from __future__ import annotations

from app.services.modelbuilding.models import SystemModelDraft
from app.services.systemmodel.models import (
    Asset,
    Component,
    Dataflow,
    DeclaredControl,
    SystemModel,
    TrustZone,
)

UNCLASSIFIED_ZONE_ID = "tz-unclassified"

# A documented heuristic, not an authoritative rating — same "visible
# default, never presented as ground truth" spirit as the rest of this
# plan's inferred-mapping code. Real risk-scoring is out of scope here.
_CLASSIFICATION_RISK: dict[str, tuple[int, int, int]] = {
    "unclassified": (1, 1, 1),
    "internal": (3, 3, 3),
    "confidential": (7, 5, 5),
    "restricted": (9, 7, 5),
    "pii": (8, 5, 5),
    "pci": (9, 7, 7),
    "phi": (9, 7, 7),
}
_DEFAULT_RISK = (1, 1, 1)


def _classification_risk(classification: str | None) -> tuple[int, int, int]:
    if classification is None:
        return _DEFAULT_RISK
    return _CLASSIFICATION_RISK.get(classification.strip().lower(), _DEFAULT_RISK)


def freeze_draft(draft: SystemModelDraft, model_id: str) -> SystemModel:
    change_summary: list[str] = []
    trust_zones = [
        TrustZone(id=zone.id, name=zone.name, trust_rating=1, provenance="agent_generated")
        for zone in draft.trust_zones
    ]
    zoned_ids = {zone.id for zone in draft.trust_zones}

    # actors never carry a trust_zone_id in the draft, so every actor counts as unzoned
    unzoned_count = sum(1 for c in draft.components if c.trust_zone_id not in zoned_ids)
    unzoned_count += len(draft.actors)
    if unzoned_count > 0:
        trust_zones.append(
            TrustZone(
                id=UNCLASSIFIED_ZONE_ID,
                name="Unclassified Zone",
                trust_rating=1,
                description="Auto-created to hold elements the source material never placed "
                "in an explicit trust boundary.",
                provenance="agent_generated",
            )
        )
        change_summary.append(
            f"assigned {unzoned_count} element(s) with no stated trust zone to an "
            "auto-created 'Unclassified Zone'"
        )

    def _zone_for(trust_zone_id: str | None) -> str:
        if trust_zone_id is not None and trust_zone_id in zoned_ids:
            return trust_zone_id
        return UNCLASSIFIED_ZONE_ID

    components = [
        Component(
            id=c.id,
            name=c.name,
            kind=c.kind,
            trust_zone_id=_zone_for(c.trust_zone_id),
            technology_tags=c.technology_tags,
            provenance="agent_generated",
        )
        for c in draft.components
    ]
    components.extend(
        Component(
            id=a.id,
            name=a.name,
            kind=a.kind,
            trust_zone_id=UNCLASSIFIED_ZONE_ID,
            technology_tags=(),
            provenance="agent_generated",
        )
        for a in draft.actors
    )

    dataflows = [
        Dataflow(
            id=f.id,
            name=f.label,
            source_id=f.source_id,
            destination_id=f.target_id,
            bidirectional=False,
            protocol=f.protocol,
            authenticated=f.authenticated,
            encrypted=f.encrypted,
            provenance="agent_generated",
        )
        for f in draft.flows
    ]

    assets = []
    for a in draft.assets:
        confidentiality, integrity, availability = _classification_risk(a.classification)
        assets.append(
            Asset(
                id=a.id,
                name=a.name,
                classification=a.classification,
                confidentiality=confidentiality,
                integrity=integrity,
                availability=availability,
                owner_id=a.owner_id,
                provenance="agent_generated",
            )
        )

    declared_controls = [
        DeclaredControl(
            id=c.id,
            name=c.name,
            applies_to_ids=c.applies_to_ids,
            provenance="agent_generated",
        )
        for c in draft.declared_controls
    ]

    change_summary.append(
        f"froze {len(components)} component(s), {len(dataflows)} dataflow(s), "
        f"{len(assets)} asset(s), {len(trust_zones)} trust zone(s), "
        f"{len(declared_controls)} declared control(s) from the model-building draft"
    )

    return SystemModel(
        id=model_id,
        version=1,
        parent_version=None,
        trust_zones=trust_zones,
        components=components,
        dataflows=dataflows,
        assets=assets,
        out_of_scope=[],
        declared_controls=declared_controls,
        change_summary=change_summary,
    )
