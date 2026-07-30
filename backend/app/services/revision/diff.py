"""Task 19's revision diff: a pure function over two immutable
`RevisionSnapshot`s — deterministic by construction (same two snapshots
always produce the same diff), and symmetric under swap: `compute_diff(b,
a)` is `compute_diff(a, b)` with every delta negated and new/removed path
ids swapped (tested explicitly in `test_revision_diff.py`).
"""

from __future__ import annotations

from app.services.revision.models import (
    CSFMovement,
    PathLikelihoodChange,
    RevisionDiff,
    RevisionSnapshot,
)


def compute_diff(parent: RevisionSnapshot, child: RevisionSnapshot) -> RevisionDiff:
    parent_paths = {p.id: p for p in parent.paths}
    child_paths = {p.id: p for p in child.paths}

    new_path_ids = tuple(sorted(set(child_paths) - set(parent_paths)))
    removed_path_ids = tuple(sorted(set(parent_paths) - set(child_paths)))

    changed_paths = tuple(
        PathLikelihoodChange(
            path_id=path_id,
            previous_likelihood=parent_paths[path_id].aggregate_likelihood,
            new_likelihood=child_paths[path_id].aggregate_likelihood,
        )
        for path_id in sorted(set(parent_paths) & set(child_paths))
        if parent_paths[path_id].aggregate_likelihood != child_paths[path_id].aggregate_likelihood
    )

    parent_verdicts = {a.candidate_threat_id: a.verdict for a in parent.adjudications}
    child_verdicts = {a.candidate_threat_id: a.verdict for a in child.adjudications}
    reopened_adjudication_ids = tuple(
        sorted(
            candidate_id
            for candidate_id, parent_verdict in parent_verdicts.items()
            if parent_verdict == "not_applicable"
            and child_verdicts.get(candidate_id) == "applicable"
        )
    )

    parent_csf = {c.function: c.unsatisfied_density for c in parent.csf_rollup}
    child_csf = {c.function: c.unsatisfied_density for c in child.csf_rollup}
    csf_rollup_movement = tuple(
        CSFMovement(
            function=function,
            previous_density=parent_csf.get(function, 0.0),
            new_density=child_csf.get(function, 0.0),
        )
        for function in sorted(set(parent_csf) | set(child_csf))
    )

    return RevisionDiff(
        new_path_ids=new_path_ids,
        removed_path_ids=removed_path_ids,
        changed_paths=changed_paths,
        reopened_adjudication_ids=reopened_adjudication_ids,
        risk_score_delta=child.risk_total_score - parent.risk_total_score,
        csf_rollup_movement=csf_rollup_movement,
        confidence_delta=child.confidence - parent.confidence,
    )
