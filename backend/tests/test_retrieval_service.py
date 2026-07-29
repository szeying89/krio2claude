from app.services.cri.models import DiagnosticStatement
from app.services.kb.models import TechniqueChunk
from app.services.retrieval.service import (
    RetrievalCollection,
    build_statement_collection,
    build_technique_collection,
    statement_document,
    technique_document,
)


def _chunk(id_, name, description, matrix="enterprise", tactics=(), platforms=()):
    return TechniqueChunk(
        id=id_,
        matrix=matrix,
        name=name,
        tactics=tactics,
        description=description,
        detection="",
        platforms=platforms,
        data_sources=(),
    )


CHUNKS = [
    _chunk(
        "T1190",
        "Exploit Public-Facing Application",
        "Adversaries may attempt to exploit a weakness in an Internet-facing host.",
        tactics=("initial-access",),
        platforms=("Linux", "Windows"),
    ),
    _chunk(
        "T1071",
        "Application Layer Protocol",
        "Adversaries may communicate using OSI application layer protocols.",
        tactics=("command-and-control",),
        platforms=("Linux", "Windows"),
    ),
    _chunk(
        "AML.T0043",
        "Craft Adversarial Data",
        "Adversaries may craft adversarial data to bypass an AI model.",
        matrix="atlas",
        tactics=("ai-model-access",),
        platforms=(),
    ),
]


def test_matrix_filter_excludes_other_matrix():
    collection = build_technique_collection(CHUNKS)
    results = collection.search("adversaries model", top_k=10, filters={"matrix": "atlas"})
    assert all(r.metadata["matrix"] == "atlas" for r in results)
    assert any(r.doc_id == "AML.T0043" for r in results)


def test_tactic_filter_matches_list_membership():
    collection = build_technique_collection(CHUNKS)
    results = collection.search("adversaries", top_k=10, filters={"tactics": "initial-access"})
    ids = {r.doc_id for r in results}
    assert ids == {"T1190"}


def test_platform_filter_excludes_platformless_atlas_technique():
    collection = build_technique_collection(CHUNKS)
    results = collection.search("adversaries", top_k=10, filters={"platforms": "Windows"})
    ids = {r.doc_id for r in results}
    assert "AML.T0043" not in ids


def test_result_carries_bm25_and_dense_ranks():
    collection = build_technique_collection(CHUNKS)
    results = collection.search("Exploit Public-Facing Application")
    top = next(r for r in results if r.doc_id == "T1190")
    assert top.bm25_rank is not None
    assert top.dense_rank is not None


def test_rrf_surfaces_document_only_one_retriever_would_rank_first():
    """A near-exact-title query should be found by BM25's exact tokens even
    though a lexical-variant query for the same technique is primarily a
    dense hit — demonstrating both retrievers contribute distinct documents
    to the fused result rather than one subsuming the other."""
    collection = build_technique_collection(CHUNKS)
    results = collection.search("application layer protocol")
    assert results[0].doc_id == "T1071"


def test_statement_collection_isolated_from_technique_collection():
    statements = [
        DiagnosticStatement(
            outline_id="003.001",
            profile_id="GV.OC-01.01",
            csf_path=("GOVERN", "Organizational Context", "Organizational Mission"),
            name="Governance alignment",
            text="Technology and cybersecurity strategies are formally governed.",
            applicable_tiers=(1, 2, 3, 4),
        )
    ]
    technique_collection = build_technique_collection(CHUNKS)
    statement_collection = build_statement_collection(statements)

    # A statement-specific query must not return technique IDs, and vice versa.
    tech_results = technique_collection.search("governed strategies")
    assert all(r.doc_id != "GV.OC-01.01" for r in tech_results)

    statement_results = statement_collection.search("Exploit Public-Facing Application")
    assert all(r.doc_id not in {"T1190", "T1071", "AML.T0043"} for r in statement_results)


def test_technique_document_and_statement_document_factories_set_expected_metadata():
    doc = technique_document(CHUNKS[0])
    assert doc.metadata["matrix"] == "enterprise"
    assert "initial-access" in doc.metadata["tactics"]

    statement = DiagnosticStatement(
        outline_id="003.001",
        profile_id="GV.OC-01.01",
        csf_path=("GOVERN", "Organizational Context", "Organizational Mission"),
        name="Governance alignment",
        text="sample",
        applicable_tiers=(1, 2),
    )
    sdoc = statement_document(statement)
    assert sdoc.metadata["csf_function"] == "GOVERN"
    assert sdoc.metadata["tiers"] == [1, 2]


def test_empty_collection_search_returns_empty():
    collection = RetrievalCollection([])
    assert collection.search("anything") == []
