"""Retrieval playground: query a KB snapshot's technique collection or a
CRI snapshot's diagnostic-statement collection via hybrid (BM25 + dense,
RRF-fused) search.

Built collections are cached per content hash for the life of the process
— snapshots are immutable, so there's nothing to invalidate.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query

from app.api.schemas import RetrievalResultOut
from app.core.config import get_settings
from app.services.cri.models import DiagnosticStatement
from app.services.kb.snapshot import read_techniques
from app.services.retrieval.service import (
    RetrievalCollection,
    build_statement_collection,
    build_technique_collection,
)

router = APIRouter(tags=["retrieval"])

_technique_collections: dict[str, RetrievalCollection] = {}
_statement_collections: dict[str, RetrievalCollection] = {}


def _get_technique_collection(content_hash: str) -> RetrievalCollection:
    if content_hash not in _technique_collections:
        snapshot_dir = get_settings().kb_dir / content_hash
        if not snapshot_dir.is_dir():
            raise HTTPException(status_code=404, detail="KB snapshot not found")
        techniques = read_techniques(snapshot_dir)
        _technique_collections[content_hash] = build_technique_collection(techniques)
    return _technique_collections[content_hash]


def _get_statement_collection(content_hash: str) -> RetrievalCollection:
    if content_hash not in _statement_collections:
        snapshot_dir = get_settings().cri_dir / content_hash
        if not snapshot_dir.is_dir():
            raise HTTPException(status_code=404, detail="CRI snapshot not found")
        raw = json.loads((snapshot_dir / "statements.json").read_text())
        statements = [DiagnosticStatement.from_dict(d) for d in raw]
        _statement_collections[content_hash] = build_statement_collection(statements)
    return _statement_collections[content_hash]


def _to_results(collection: RetrievalCollection, q: str, top_k: int, filters: dict[str, str]) -> list[RetrievalResultOut]:
    results = collection.search(q, top_k=top_k, filters=filters or None)
    return [
        RetrievalResultOut(
            doc_id=r.doc_id,
            fused_score=r.fused_score,
            bm25_rank=r.bm25_rank,
            dense_rank=r.dense_rank,
            snippet=r.snippet,
            metadata=r.metadata,
        )
        for r in results
    ]


@router.get("/kb/snapshots/{content_hash}/retrieval", response_model=list[RetrievalResultOut])
async def search_techniques(
    content_hash: str,
    q: str,
    top_k: int = Query(default=10, ge=1, le=100),
    matrix: str | None = None,
    tactic: str | None = None,
    platform: str | None = None,
) -> list[RetrievalResultOut]:
    collection = _get_technique_collection(content_hash)
    filters: dict[str, str] = {}
    if matrix:
        filters["matrix"] = matrix
    if tactic:
        filters["tactics"] = tactic
    if platform:
        filters["platforms"] = platform
    return _to_results(collection, q, top_k, filters)


@router.get("/cri/snapshots/{content_hash}/retrieval", response_model=list[RetrievalResultOut])
async def search_statements(
    content_hash: str,
    q: str,
    top_k: int = Query(default=10, ge=1, le=100),
    csf_function: str | None = None,
) -> list[RetrievalResultOut]:
    collection = _get_statement_collection(content_hash)
    filters: dict[str, str] = {}
    if csf_function:
        filters["csf_function"] = csf_function
    return _to_results(collection, q, top_k, filters)
