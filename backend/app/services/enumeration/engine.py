"""STRIDE-per-element and LINDDUN enumeration (Task 10): a deterministic
tool, zero LLM calls. The Enumeration Agent calls this; it never reasons
about which categories apply — the ruleset decides that, not the agent.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.ruleset import Ruleset
from app.services.systemmodel.models import SystemModel


@dataclass(frozen=True)
class CandidateThreat:
    id: str
    element_id: str
    element_kind: str
    framework: str  # "stride" | "linddun"
    category: str
    ruleset_version: str


def _candidate_id(element_id: str, category: str, ruleset_version: str) -> str:
    return f"{element_id}::{category}::{ruleset_version}"


def _stride_categories_for(kind: str, tags: tuple[str, ...], ruleset: Ruleset) -> list[str]:
    lowered_tags = {t.lower() for t in tags}
    categories: list[str] = []
    for rule in ruleset.element_rules:
        if rule.match_kind != kind:
            continue
        if rule.match_tag is not None and rule.match_tag.lower() not in lowered_tags:
            continue
        for category in rule.categories:
            if category.value not in categories:
                categories.append(category.value)
    return categories


def _is_personal_data(
    classification: str | None, tags: tuple[str, ...], ruleset: Ruleset
) -> bool:
    if classification is not None and classification.strip().lower() in {
        c.lower() for c in ruleset.linddun_personal_data_classifications
    }:
        return True
    lowered_tags = {t.lower() for t in tags}
    return any(tag.lower() in lowered_tags for tag in ruleset.linddun_personal_data_tags)


def _personal_data_component_ids(model: SystemModel, ruleset: Ruleset) -> set[str]:
    ids: set[str] = set()
    for component in model.components:
        if _is_personal_data(None, component.technology_tags, ruleset):
            ids.add(component.id)
    for asset in model.assets:
        if asset.owner_id is None:
            continue
        if _is_personal_data(asset.classification, (), ruleset):
            ids.add(asset.owner_id)
    return ids


def enumerate_threats(model: SystemModel, ruleset: Ruleset) -> list[CandidateThreat]:
    """Out-of-scope components (Task 9's OT/ICS and mobile-client
    detector) generate zero candidates here — they stay in the model for
    context, but per the plan are "excluded from enumeration". A dataflow
    is excluded only when *both* endpoints are out of scope; a flow
    touching one in-scope element still matters from that element's side.
    """
    candidates: list[CandidateThreat] = []
    personal_data_ids = _personal_data_component_ids(model, ruleset)
    out_of_scope_ids = {c.id for c in model.components if c.out_of_scope}

    for component in model.components:
        if component.out_of_scope:
            continue
        for category in _stride_categories_for(component.kind, component.technology_tags, ruleset):
            candidates.append(
                CandidateThreat(
                    id=_candidate_id(component.id, category, ruleset.version),
                    element_id=component.id,
                    element_kind=component.kind,
                    framework="stride",
                    category=category,
                    ruleset_version=ruleset.version,
                )
            )
        if component.id in personal_data_ids:
            for linddun_category in ruleset.linddun_categories:
                candidates.append(
                    CandidateThreat(
                        id=_candidate_id(component.id, linddun_category.value, ruleset.version),
                        element_id=component.id,
                        element_kind=component.kind,
                        framework="linddun",
                        category=linddun_category.value,
                        ruleset_version=ruleset.version,
                    )
                )

    for flow in model.dataflows:
        if flow.source_id in out_of_scope_ids and flow.destination_id in out_of_scope_ids:
            continue
        for category in _stride_categories_for("dataflow", (), ruleset):
            candidates.append(
                CandidateThreat(
                    id=_candidate_id(flow.id, category, ruleset.version),
                    element_id=flow.id,
                    element_kind="dataflow",
                    framework="stride",
                    category=category,
                    ruleset_version=ruleset.version,
                )
            )
        touches_personal_data = flow.source_id in personal_data_ids or flow.destination_id in personal_data_ids
        if touches_personal_data:
            for linddun_category in ruleset.linddun_categories:
                candidates.append(
                    CandidateThreat(
                        id=_candidate_id(flow.id, linddun_category.value, ruleset.version),
                        element_id=flow.id,
                        element_kind="dataflow",
                        framework="linddun",
                        category=linddun_category.value,
                        ruleset_version=ruleset.version,
                    )
                )

    return candidates
