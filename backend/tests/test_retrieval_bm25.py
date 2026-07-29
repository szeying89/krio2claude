from app.services.retrieval.bm25_index import BM25Index
from app.services.retrieval.models import RetrievableDocument

DOCS = [
    RetrievableDocument("T1190", "T1190 Exploit Public-Facing Application vulnerability web server"),
    RetrievableDocument("T1071", "T1071 Application Layer Protocol command and control communication"),
    RetrievableDocument("T1110", "T1110 Brute Force credential guessing password spraying"),
]


def test_exact_id_lookup_wins():
    index = BM25Index(DOCS)
    results = index.search("T1190", top_k=3)
    assert results[0][0] == "T1190"


def test_relevant_keyword_query_ranks_matching_doc_first():
    index = BM25Index(DOCS)
    results = index.search("brute force password", top_k=3)
    assert results[0][0] == "T1110"


def test_no_match_returns_empty():
    index = BM25Index(DOCS)
    assert index.search("zzz_no_such_term_zzz") == []


def test_empty_query_returns_empty():
    index = BM25Index(DOCS)
    assert index.search("") == []


def test_higher_score_is_better():
    index = BM25Index(DOCS)
    results = index.search("application protocol")
    scores = [score for _, score in results]
    assert scores == sorted(scores, reverse=True)


def test_query_with_quotes_and_operators_does_not_raise():
    index = BM25Index(DOCS)
    # FTS5 query syntax characters (quotes, hyphen-as-NOT, etc.) must be
    # treated as literal terms, not crash the query.
    index.search('"weird" -query* OR AND NOT (parens)')


def test_identical_query_returns_identical_ordering():
    index = BM25Index(DOCS)
    first = index.search("application")
    second = index.search("application")
    assert first == second
