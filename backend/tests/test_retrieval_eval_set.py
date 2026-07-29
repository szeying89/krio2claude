"""Labelled retrieval eval set (Task 5): exact-ID lookups, Enterprise
paraphrases, ATLAS/ML phrasing, and CRI statement retrieval, with recall@k
assertions — the kind of check meant to run in CI to catch retrieval
regressions, not just unit-test individual components."""

from app.services.retrieval.bm25_index import BM25Index
from app.services.retrieval.dense_index import DenseIndex
from app.services.retrieval.service import (
    build_statement_collection,
    build_technique_collection,
    statement_document,
    technique_document,
)
from tests.retrieval_fixtures import sample_diagnostic_statements, sample_technique_chunks

TECHNIQUE_EVAL_SET = [
    ("T1190", "T1190", "exact_id"),
    ("T1003", "T1003", "exact_id"),
    ("AML.T0043", "AML.T0043", "exact_id"),
    ("exploiting a public facing app to get initial access", "T1190", "enterprise_paraphrase"),
    ("bruteforcing creds", "T1110", "enterprise_paraphrase"),
    ("dumping OS credentials and passwords from memory", "T1003", "enterprise_paraphrase"),
    ("hiding files by encoding and obfuscating their content", "T1027", "enterprise_paraphrase"),
    ("crafting adversarial inputs to fool a machine learning model", "AML.T0043", "atlas_ml_phrasing"),
    ("poisoning the training dataset of an AI model", "AML.T0020", "atlas_ml_phrasing"),
    ("stealing a model by querying its inference api repeatedly", "AML.T0024", "atlas_ml_phrasing"),
    ("backdoor trigger hidden inside a trained model", "AML.T0018", "atlas_ml_phrasing"),
]

STATEMENT_EVAL_SET = [
    ("privileged access controls with multi-factor authentication", "PR.AA-05.01", "cri_statement"),
    ("monitoring network traffic for command and control activity", "DE.CM-01.03", "cri_statement"),
    ("testing backup restoration for recovery objectives", "RC.RP-01.02", "cri_statement"),
]


def _recall_at_k(collection, eval_set, k=3) -> float:
    hits = 0
    for query, expected_id, _category in eval_set:
        results = collection.search(query, top_k=k)
        if any(r.doc_id == expected_id for r in results):
            hits += 1
    return hits / len(eval_set)


def test_technique_eval_set_recall_at_3():
    collection = build_technique_collection(sample_technique_chunks())
    recall = _recall_at_k(collection, TECHNIQUE_EVAL_SET, k=3)
    assert recall >= 0.9, f"recall@3 too low: {recall}"


def test_statement_eval_set_recall_at_3():
    collection = build_statement_collection(sample_diagnostic_statements())
    recall = _recall_at_k(collection, STATEMENT_EVAL_SET, k=3)
    assert recall == 1.0, f"recall@3 too low: {recall}"


def test_bm25_wins_exact_id_lookup():
    chunks = sample_technique_chunks()
    docs = [technique_document(c) for c in chunks]
    bm25 = BM25Index(docs)
    results = bm25.search("T1190", top_k=1)
    assert results and results[0][0] == "T1190"


def test_dense_wins_a_paraphrase_bm25_ranks_poorly():
    chunks = sample_technique_chunks()
    docs = [technique_document(c) for c in chunks]
    bm25 = BM25Index(docs)
    dense = DenseIndex(docs)

    query = "bruteforcing creds"
    bm25_ids = [doc_id for doc_id, _ in bm25.search(query, top_k=3)]
    dense_ids = [doc_id for doc_id, _ in dense.search(query, top_k=3)]

    assert "T1110" not in bm25_ids
    assert dense_ids and dense_ids[0] == "T1110"


def test_rrf_recovers_documents_that_either_retriever_alone_would_miss():
    """Across the full eval set, fused recall@3 must be at least as good as
    either individual retriever's recall@3 — the point of hybrid retrieval."""
    chunks = sample_technique_chunks()
    docs = [technique_document(c) for c in chunks]
    bm25 = BM25Index(docs)
    dense = DenseIndex(docs)
    fused_collection = build_technique_collection(chunks)

    def recall_for(search_fn) -> float:
        hits = 0
        for query, expected_id, _category in TECHNIQUE_EVAL_SET:
            ids = [doc_id for doc_id, _ in search_fn(query, 3)]
            if expected_id in ids:
                hits += 1
        return hits / len(TECHNIQUE_EVAL_SET)

    bm25_recall = recall_for(lambda q, k: bm25.search(q, top_k=k))
    dense_recall = recall_for(lambda q, k: dense.search(q, top_k=k))
    fused_recall = _recall_at_k(fused_collection, TECHNIQUE_EVAL_SET, k=3)

    assert fused_recall >= bm25_recall
    assert fused_recall >= dense_recall
    assert fused_recall > min(bm25_recall, dense_recall)


def test_cri_statement_document_factory_used_consistently():
    statements = sample_diagnostic_statements()
    doc = statement_document(statements[0])
    assert doc.id == "GV.OC-01.01"
