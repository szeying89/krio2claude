"""Per-collection hybrid retrieval: BM25 + dense, fused by RRF, with
post-fusion metadata filtering (matrix, tactic, platform, ...).

Two independent collections exist — technique chunks (ATT&CK Enterprise +
ATLAS) and CRI diagnostic statements — built via the factory functions
below and never sharing an index, so a technique query can't leak into
statement results or vice versa.
"""

from __future__ import annotations

from app.services.cri.models import DiagnosticStatement
from app.services.kb.models import TechniqueChunk
from app.services.retrieval.bm25_index import BM25Index
from app.services.retrieval.dense_index import DenseIndex, Embedder
from app.services.retrieval.models import RetrievableDocument, ScoredResult
from app.services.retrieval.rrf import reciprocal_rank_fusion


class RetrievalCollection:
    def __init__(
        self, documents: list[RetrievableDocument], embedder: Embedder | None = None
    ) -> None:
        self._by_id = {doc.id: doc for doc in documents}
        self._bm25 = BM25Index(documents)
        self._dense = DenseIndex(documents, embedder=embedder)

    def search(
        self,
        query: str,
        top_k: int = 10,
        filters: dict[str, str] | None = None,
        candidate_pool: int = 50,
    ) -> list[ScoredResult]:
        bm25_hits = self._bm25.search(query, top_k=candidate_pool)
        dense_hits = self._dense.search(query, top_k=candidate_pool)

        bm25_ranked_ids = [doc_id for doc_id, _ in bm25_hits]
        dense_ranked_ids = [doc_id for doc_id, _ in dense_hits]
        fused = reciprocal_rank_fusion([bm25_ranked_ids, dense_ranked_ids])

        bm25_rank_by_id = {doc_id: i + 1 for i, doc_id in enumerate(bm25_ranked_ids)}
        dense_rank_by_id = {doc_id: i + 1 for i, doc_id in enumerate(dense_ranked_ids)}

        results: list[ScoredResult] = []
        for doc_id, fused_score in fused:
            doc = self._by_id.get(doc_id)
            if doc is None:
                continue
            if filters and not _matches_filters(doc, filters):
                continue
            results.append(
                ScoredResult(
                    doc_id=doc_id,
                    fused_score=fused_score,
                    bm25_rank=bm25_rank_by_id.get(doc_id),
                    dense_rank=dense_rank_by_id.get(doc_id),
                    snippet=doc.text[:240],
                    metadata=doc.metadata,
                )
            )
            if len(results) >= top_k:
                break
        return results

    def close(self) -> None:
        self._bm25.close()


def _matches_filters(doc: RetrievableDocument, filters: dict[str, str]) -> bool:
    for key, value in filters.items():
        doc_value = doc.metadata.get(key)
        if doc_value is None:
            return False
        if isinstance(doc_value, list | tuple):
            if value not in doc_value:
                return False
        elif doc_value != value:
            return False
    return True


def technique_document(chunk: TechniqueChunk) -> RetrievableDocument:
    text = " ".join(filter(None, [chunk.id, chunk.name, chunk.description, chunk.detection]))
    return RetrievableDocument(
        id=chunk.id,
        text=text,
        metadata={
            "matrix": chunk.matrix,
            "tactics": list(chunk.tactics),
            "platforms": list(chunk.platforms),
            "name": chunk.name,
        },
    )


def build_technique_collection(
    chunks: list[TechniqueChunk], embedder: Embedder | None = None
) -> RetrievalCollection:
    return RetrievalCollection([technique_document(c) for c in chunks], embedder=embedder)


def statement_document(statement: DiagnosticStatement) -> RetrievableDocument:
    text = " ".join(
        filter(
            None,
            [statement.profile_id, statement.name, statement.text, *statement.subject_tags],
        )
    )
    return RetrievableDocument(
        id=statement.profile_id,
        text=text,
        metadata={
            "csf_function": statement.csf_path[0] if statement.csf_path else "",
            "tiers": list(statement.applicable_tiers),
            "name": statement.name,
        },
    )


def build_statement_collection(
    statements: list[DiagnosticStatement], embedder: Embedder | None = None
) -> RetrievalCollection:
    return RetrievalCollection([statement_document(s) for s in statements], embedder=embedder)
