"""Generic retrieval document model.

Both the technique collection (ATT&CK Enterprise + ATLAS) and the CRI
diagnostic-statement collection are indexed through this same shape, kept
deliberately minimal so the retrieval machinery (BM25, dense, RRF) has no
dependency on either domain's richer model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RetrievableDocument:
    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoredResult:
    doc_id: str
    fused_score: float
    bm25_rank: int | None
    dense_rank: int | None
    snippet: str
    metadata: dict[str, Any]
