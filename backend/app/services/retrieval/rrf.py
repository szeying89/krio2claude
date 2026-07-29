"""Reciprocal rank fusion.

score(d) = sum over each ranked list containing d of 1 / (k + rank), where
rank is 1-based. A document absent from a given list contributes nothing
for that list. Deterministic: ties break on doc_id so identical inputs
always produce identical output ordering.
"""

from __future__ import annotations

DEFAULT_K = 60


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]], k: int = DEFAULT_K
) -> list[tuple[str, float]]:
    scores: dict[str, float] = {}
    for ranked_list in ranked_lists:
        for rank, doc_id in enumerate(ranked_list, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)

    return sorted(scores.items(), key=lambda pair: (-pair[1], pair[0]))
