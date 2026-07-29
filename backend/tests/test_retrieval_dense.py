from app.services.retrieval.bm25_index import BM25Index
from app.services.retrieval.dense_index import DenseIndex
from app.services.retrieval.models import RetrievableDocument

DOCS = [
    RetrievableDocument("T1190", "Exploit Public-Facing Application"),
    RetrievableDocument("T1071", "Application Layer Protocol"),
    RetrievableDocument("T1110", "Brute Force"),
]


def test_exact_text_scores_highest_against_itself():
    index = DenseIndex(DOCS)
    results = index.search("Exploit Public-Facing Application")
    assert results[0][0] == "T1190"


def test_hyphenation_variant_still_matches_via_char_ngrams():
    # "Public Facing" (no hyphen) vs the corpus's "Public-Facing" — exact
    # word-token BM25 would treat these as different tokens; char n-grams
    # still overlap heavily.
    index = DenseIndex(DOCS)
    results = index.search("exploiting a public facing application")
    assert results[0][0] == "T1190"


def test_unrelated_query_scores_near_zero_or_empty():
    index = DenseIndex(DOCS)
    results = index.search("zzz completely unrelated gibberish qqq")
    if results:
        assert results[0][1] < 0.3


def test_empty_query_returns_empty():
    index = DenseIndex(DOCS)
    assert index.search("") == []


def test_empty_corpus_returns_empty():
    index = DenseIndex([])
    assert index.search("anything") == []


def test_identical_query_returns_identical_ordering():
    index = DenseIndex(DOCS)
    first = index.search("application protocol")
    second = index.search("application protocol")
    assert first == second


def test_dense_catches_a_paraphrase_that_bm25_misses():
    """The whole point of hybrid retrieval: a lexical variant that shares
    almost no exact word tokens with the target document should still be
    found by the char-ngram dense index, even where BM25 (exact-token
    matching) returns nothing relevant."""
    docs = [
        RetrievableDocument("T1110", "Brute Force"),
        RetrievableDocument("T1071", "Application Layer Protocol"),
    ]
    query = "bruteforcing credentials"  # "bruteforcing" shares no token with "Brute Force"

    bm25 = BM25Index(docs)
    dense = DenseIndex(docs)

    bm25_hits = [doc_id for doc_id, _ in bm25.search(query)]
    dense_hits = [doc_id for doc_id, _ in dense.search(query)]

    assert "T1110" not in bm25_hits
    assert dense_hits and dense_hits[0] == "T1110"
