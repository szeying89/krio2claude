"""Dense retrieval, with a pluggable embedder.

The plan calls for "dense embeddings in a local vector store." A neural
sentence-embedding model would be the real implementation, but this
sandbox's network policy blocks huggingface.co (the same class of
restriction documented for d3fend.mitre.org in app/services/kb/fetchers.py),
so there is no way to verify a model download from here.

Rather than fake a neural embedder, `LexicalCharNgramEmbedder` is an honest,
deterministic, network-free proxy: TF-IDF over character n-grams. It
genuinely captures a different similarity signal than exact-token BM25 —
reordering, inflection, hyphenation variants, partial substrings — but it is
*lexical*, not semantic; it will not catch true synonyms. `Embedder` is a
narrow fit/transform protocol so a real embedding provider can be swapped in
later (mirroring the injectable-fetcher pattern in app/services/kb/
fetchers.py) without touching DenseIndex or the retrieval service above it.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.services.retrieval.models import RetrievableDocument


class Embedder(Protocol):
    def fit(self, texts: list[str]) -> None: ...
    def transform(self, texts: list[str]) -> np.ndarray: ...


class LexicalCharNgramEmbedder:
    def __init__(self) -> None:
        self._vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        self._fitted = False

    def fit(self, texts: list[str]) -> None:
        self._vectorizer.fit(texts)
        self._fitted = True

    def transform(self, texts: list[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("embedder must be fit before transform")
        return self._vectorizer.transform(texts).toarray()


class DenseIndex:
    def __init__(
        self, documents: list[RetrievableDocument], embedder: Embedder | None = None
    ) -> None:
        self._embedder = embedder or LexicalCharNgramEmbedder()
        self._doc_ids = [doc.id for doc in documents]
        texts = [doc.text for doc in documents]
        if texts:
            self._embedder.fit(texts)
            self._doc_vectors = self._embedder.transform(texts)
        else:
            self._doc_vectors = np.zeros((0, 0))

    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float]]:
        query = query.strip()
        if not query or not self._doc_ids:
            return []
        query_vector = self._embedder.transform([query])
        scores = cosine_similarity(query_vector, self._doc_vectors)[0]
        ranked = sorted(zip(self._doc_ids, scores, strict=True), key=lambda p: (-p[1], p[0]))
        return [(doc_id, float(score)) for doc_id, score in ranked[:top_k] if score > 0]
