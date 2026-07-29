"""BM25 sparse retrieval over an in-memory SQLite FTS5 index.

Built fresh per collection (a KB snapshot's techniques, or a CRI snapshot's
diagnostic statements) — corpora here are at most a few thousand documents,
so an in-memory FTS5 table rebuilds in well under a second and needs no
on-disk persistence of its own (the source data is already the persisted,
content-hashed snapshot).
"""

from __future__ import annotations

import sqlite3

from app.services.retrieval.models import RetrievableDocument


class BM25Index:
    def __init__(self, documents: list[RetrievableDocument]) -> None:
        self._connection = sqlite3.connect(":memory:")
        self._connection.execute(
            "CREATE VIRTUAL TABLE docs USING fts5(doc_id UNINDEXED, text, tokenize='porter')"
        )
        self._connection.executemany(
            "INSERT INTO docs (doc_id, text) VALUES (?, ?)",
            [(doc.id, doc.text) for doc in documents],
        )
        self._connection.commit()

    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float]]:
        query = query.strip()
        if not query:
            return []
        try:
            rows = self._connection.execute(
                "SELECT doc_id, bm25(docs) AS score FROM docs "
                "WHERE docs MATCH ? ORDER BY score LIMIT ?",
                (_escape_fts_query(query), top_k),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        # SQLite's bm25() returns *lower is better*; invert so higher is better,
        # consistent with the dense index and RRF's expectations.
        return [(doc_id, -score) for doc_id, score in rows]

    def close(self) -> None:
        self._connection.close()


def _escape_fts_query(query: str) -> str:
    """Treat the query as a bag of OR'd terms rather than FTS5 query syntax
    — user input shouldn't need to know about FTS5 operators, and a stray
    quote or operator character shouldn't raise a syntax error."""
    tokens = [t for t in query.replace('"', " ").split() if t]
    escaped = [f'"{t}"' for t in tokens]
    return " OR ".join(escaped) if escaped else '""'
