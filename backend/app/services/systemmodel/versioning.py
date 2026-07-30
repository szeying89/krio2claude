"""Diffing between two `SystemModel` versions of the same model.

Produces the human-readable `change_summary` lines a new version carries —
"diffable provenance" per the plan: not a byte diff, but a structural one
(elements added, removed, or changed) keyed by each entity's own stable id,
so an edit to one component doesn't get lost in noise from unrelated
elements.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any

from app.services.systemmodel.models import SystemModel


def _by_id(items: list[Any]) -> dict[str, Any]:
    return {item.id: item for item in items}


def diff_models(previous: SystemModel | None, current: SystemModel) -> list[str]:
    if previous is None:
        summary = (
            f"initial version: {len(current.components)} component(s), "
            f"{len(current.dataflows)} dataflow(s), {len(current.assets)} asset(s), "
            f"{len(current.trust_zones)} trust zone(s)"
        )
        return [summary]

    lines: list[str] = []
    for attr, label in (
        ("trust_zones", "trust zone"),
        ("components", "component"),
        ("dataflows", "dataflow"),
        ("assets", "asset"),
    ):
        before = _by_id(getattr(previous, attr))
        after = _by_id(getattr(current, attr))

        added = [id_ for id_ in after if id_ not in before]
        removed = [id_ for id_ in before if id_ not in after]
        changed = [
            id_
            for id_ in after
            if id_ in before and _entity_fields(after[id_]) != _entity_fields(before[id_])
        ]

        for id_ in added:
            lines.append(f"added {label} {getattr(after[id_], 'name', id_)!r} ({id_})")
        for id_ in removed:
            lines.append(f"removed {label} {getattr(before[id_], 'name', id_)!r} ({id_})")
        for id_ in changed:
            lines.append(f"changed {label} {getattr(after[id_], 'name', id_)!r} ({id_})")

    if not lines:
        lines.append("no structural changes from the previous version")
    return lines


def _entity_fields(entity: Any) -> dict[str, object]:
    return {f.name: getattr(entity, f.name) for f in fields(entity)}
