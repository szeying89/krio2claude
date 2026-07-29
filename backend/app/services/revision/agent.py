"""Task 19's revision computation wired through the orchestrator — the
"Owner: orchestrator (revision mechanics)" part of the plan. The handler
is a thin `ctx.call_tool` wrapper around `compute_snapshot` (a pure,
already-fully-tested deterministic tool); the value this AgentSpec adds
is participating in `InvalidationGraph.compute_affected` (Task 1b) like
any other agent, and a central `validate` gate independently re-checking
every surfaced adjudication's citation score — mirroring Task 14's
`validate_enumeration_grounding` split.
"""

from __future__ import annotations

from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.enumeration.grounding import DEFAULT_CITATION_THRESHOLD
from app.services.revision.models import RevisionSnapshot
from app.services.revision.snapshot import compute_snapshot

AGENT_NAME = "revision"


def build_revision_agent() -> AgentSpec:
    """input_artifacts: every positional argument `compute_snapshot`
    takes, passed through by keyword — see that function's signature."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        kwargs = dict(ctx.input_artifacts)
        snapshot: RevisionSnapshot = ctx.call_tool(
            "revision.compute_snapshot", compute_snapshot, **kwargs
        )
        return {"snapshot": snapshot}

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("system_model", "intel"),
        output_artifact_types=("snapshot",),
        handler=handler,
        max_tool_calls=5000,
    )


def validate_revision_grounding(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    snapshot: RevisionSnapshot | None = output_artifacts.get("snapshot")
    if snapshot is None:
        return
    for adjudication in snapshot.adjudications:
        if adjudication.citation_score < DEFAULT_CITATION_THRESHOLD:
            raise ValidationError(
                f"{agent_name}: candidate {adjudication.candidate_threat_id!r} reached "
                f"adjudication without a grounding citation (citation_score="
                f"{adjudication.citation_score})"
            )
