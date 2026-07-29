"""Completeness gate: a deterministic tool, zero LLM calls, that inspects a
merged `SystemModelDraft` for the four defect classes the plan calls out
by name. Any finding means the run moves to `needs_input` — resolved via
the orchestrator's invalidation graph once the clarification is answered,
never a bespoke re-run path.
"""

from __future__ import annotations

from app.services.modelbuilding.merge import ModelBuilder
from app.services.modelbuilding.models import CompletenessFinding, SystemModelDraft


def check_completeness(draft: SystemModelDraft, builder: ModelBuilder) -> list[CompletenessFinding]:
    findings: list[CompletenessFinding] = []
    findings.extend(_dangling_flows(draft))
    findings.extend(_sourceless_sinks(draft))
    findings.extend(_unclassified_assets(draft))
    findings.extend(_untagged_boundary_crossings(draft, builder))
    return findings


def _known_ids(draft: SystemModelDraft) -> set[str]:
    return {c.id for c in draft.components} | {a.id for a in draft.actors}


def _dangling_flows(draft: SystemModelDraft) -> list[CompletenessFinding]:
    known = _known_ids(draft)
    findings = []
    for flow in draft.flows:
        missing = [ref for ref in (flow.source_id, flow.target_id) if ref not in known]
        if missing:
            findings.append(
                CompletenessFinding(
                    kind="dangling_flow",
                    subject_id=flow.id,
                    message=f"flow {flow.id} references unresolved endpoint(s): {missing}",
                )
            )
    return findings


def _sourceless_sinks(draft: SystemModelDraft) -> list[CompletenessFinding]:
    incoming: set[str] = {flow.target_id for flow in draft.flows}
    findings = []
    for component in draft.components:
        if component.kind == "datastore" and component.id not in incoming:
            findings.append(
                CompletenessFinding(
                    kind="sourceless_sink",
                    subject_id=component.id,
                    message=f"data store {component.name!r} has no incoming data flow",
                )
            )
    return findings


def _unclassified_assets(draft: SystemModelDraft) -> list[CompletenessFinding]:
    findings = []
    for asset in draft.assets:
        classification = (asset.classification or "").strip().lower()
        if classification in ("", "unclassified"):
            findings.append(
                CompletenessFinding(
                    kind="unclassified_asset",
                    subject_id=asset.id,
                    message=f"asset {asset.name!r} has no data classification",
                )
            )
    return findings


def _untagged_boundary_crossings(
    draft: SystemModelDraft, builder: ModelBuilder
) -> list[CompletenessFinding]:
    findings = []
    for flow in draft.flows:
        source_zone = builder.element_trust_zone(flow.source_id)
        target_zone = builder.element_trust_zone(flow.target_id)
        crosses_boundary = source_zone != target_zone and (source_zone is not None or target_zone is not None)
        has_metadata = flow.protocol is not None or flow.authenticated is not None or flow.encrypted is not None
        if crosses_boundary and not has_metadata:
            findings.append(
                CompletenessFinding(
                    kind="untagged_boundary_crossing",
                    subject_id=flow.id,
                    message=(
                        f"flow {flow.id} crosses a trust-zone boundary "
                        f"({source_zone!r} -> {target_zone!r}) with no protocol, "
                        "authentication, or encryption stated"
                    ),
                )
            )
    return findings
