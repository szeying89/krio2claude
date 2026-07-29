from app.services.retrieval.rrf import reciprocal_rank_fusion


def test_document_in_both_lists_outranks_single_list_hit():
    bm25 = ["a", "b", "c"]
    dense = ["b", "a", "d"]
    fused = reciprocal_rank_fusion([bm25, dense])
    ids = [doc_id for doc_id, _ in fused]
    # "a" and "b" both appear in both lists near the top; "c" and "d" each
    # appear in only one list, so they must rank below "a" and "b".
    assert set(ids[:2]) == {"a", "b"}
    assert ids[2:] == sorted(["c", "d"]) or set(ids[2:]) == {"c", "d"}


def test_document_absent_from_a_list_contributes_nothing_for_it():
    fused = dict(reciprocal_rank_fusion([["x"], []]))
    assert fused["x"] == 1 / (60 + 1)


def test_deterministic_tie_break_by_doc_id():
    # "b" and "a" each appear only in their own single-item list, at rank 1,
    # so their fused scores tie exactly — the tie-break must be doc_id order.
    tied = reciprocal_rank_fusion([["b"], ["a"]])
    assert tied == [("a", 1 / 61), ("b", 1 / 61)]


def test_empty_input_returns_empty():
    assert reciprocal_rank_fusion([]) == []
    assert reciprocal_rank_fusion([[], []]) == []


def test_custom_k_changes_score_magnitude_not_ordering():
    ranked = [["a", "b", "c"]]
    low_k = dict(reciprocal_rank_fusion(ranked, k=1))
    high_k = dict(reciprocal_rank_fusion(ranked, k=1000))
    assert low_k["a"] > low_k["b"] > low_k["c"]
    assert high_k["a"] > high_k["b"] > high_k["c"]
    assert low_k["a"] > high_k["a"]
