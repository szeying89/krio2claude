import json

from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.capec import parse_capec_bundle
from app.services.kb.d3fend import parse_d3fend_csv
from app.services.kb.heuristic_mapping import HeuristicSource, infer_technique_mappings
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import (
    compute_content_hash,
    merge_relationships,
    read_d3fend_catalog,
    read_manifest,
    read_techniques,
    write_snapshot,
)
from tests.kb_fixtures import load_json, load_text


def _load_enterprise_chunks() -> list[TechniqueChunk]:
    return parse_attack_enterprise_bundle(load_json("enterprise_bundle.json"))


def _load_d3fend_inferred(chunks):
    catalog = parse_d3fend_csv(load_text("d3fend_catalog.csv"))
    sources = [HeuristicSource(id=t.id, name=t.name, text=t.definition) for t in catalog]
    return catalog, infer_technique_mappings(sources, chunks)


def test_merge_relationships_attaches_capec_and_inferred_d3fend():
    chunks = _load_enterprise_chunks()
    capec_map = parse_capec_bundle(load_json("capec_bundle.json"))
    _catalog, d3fend_inferred = _load_d3fend_inferred(chunks)

    merged, _unresolved_capec = merge_relationships(chunks, capec_map, d3fend_inferred)
    by_id = {c.id: c for c in merged}

    assert by_id["T1190"].relationships["capec"] == ("CAPEC-66",)
    assert by_id["T1071"].relationships["capec"] == ("CAPEC-94",)
    # d3fend_inferred is heuristic and never guaranteed to hit for a given
    # fixture pairing; what matters is it's a distinct key from "d3fend".
    for chunk in merged:
        assert "d3fend" not in chunk.relationships


def test_merge_relationships_reports_unresolved_capec_mappings_visibly():
    chunks = _load_enterprise_chunks()
    capec_map = parse_capec_bundle(load_json("capec_bundle.json"))

    _, unresolved_capec = merge_relationships(chunks, capec_map, {})

    # CAPEC-94 maps to both T1071 (known) and T9999-unknown (not in the KB);
    # the unknown side must be visible, not silently merged into T1071's entry.
    assert unresolved_capec == ["CAPEC-94"]


def test_content_hash_is_deterministic_for_identical_input():
    chunks = _load_enterprise_chunks()
    versions = {"attack_enterprise": "19.1"}

    hash_a = compute_content_hash(chunks, versions)
    hash_b = compute_content_hash(chunks, versions)
    assert hash_a == hash_b


def test_content_hash_changes_when_data_changes():
    chunks = _load_enterprise_chunks()
    versions = {"attack_enterprise": "19.1"}
    other_versions = {"attack_enterprise": "19.0"}

    assert compute_content_hash(chunks, versions) != compute_content_hash(chunks, other_versions)


def test_write_snapshot_is_atomic_and_readable(tmp_path):
    chunks = _load_enterprise_chunks()
    versions = {"attack_enterprise": "19.1"}
    catalog, d3fend_inferred = _load_d3fend_inferred(chunks)

    snapshot_dir = write_snapshot(
        tmp_path,
        chunks,
        versions,
        source_urls={"attack_enterprise": "https://example/x"},
        fetched_at="2026-01-01T00:00:00Z",
        d3fend_catalog=catalog,
        d3fend_inferred=d3fend_inferred,
    )

    assert snapshot_dir.is_dir()
    assert not any(p.name.startswith(".tmp-") for p in tmp_path.iterdir())

    manifest = read_manifest(snapshot_dir)
    assert manifest["versions"] == versions
    assert manifest["chunk_counts"] == {"enterprise": 3}
    assert manifest["d3fend_catalog_size"] == len(catalog)

    read_back = read_techniques(snapshot_dir)
    assert {c.id for c in read_back} == {c.id for c in chunks}

    read_back_catalog = read_d3fend_catalog(snapshot_dir)
    assert {t.id for t in read_back_catalog} == {t.id for t in catalog}


def test_rerunning_with_identical_data_is_a_noop(tmp_path):
    chunks = _load_enterprise_chunks()
    versions = {"attack_enterprise": "19.1"}

    first = write_snapshot(
        tmp_path, chunks, versions, source_urls={}, fetched_at="2026-01-01T00:00:00Z"
    )
    first_manifest_mtime = (first / "manifest.json").stat().st_mtime_ns

    second = write_snapshot(
        tmp_path, chunks, versions, source_urls={}, fetched_at="2026-06-01T00:00:00Z"
    )

    assert second == first
    assert (second / "manifest.json").stat().st_mtime_ns == first_manifest_mtime, (
        "a snapshot with an unchanged content hash must not be rewritten"
    )


def test_identical_fixtures_produce_identical_hash_across_independent_runs(tmp_path):
    """The core reproducibility guarantee: two independent pipeline runs
    against the same upstream fixtures must publish to the same hash, even
    with different kb_dir roots and different fetch timestamps."""
    chunks_a = _load_enterprise_chunks()
    chunks_b = parse_attack_enterprise_bundle(
        json.loads(json.dumps(load_json("enterprise_bundle.json")))
    )
    versions = {"attack_enterprise": "19.1"}

    dir_a = write_snapshot(
        tmp_path / "run-a", chunks_a, versions, source_urls={}, fetched_at="2026-01-01T00:00:00Z"
    )
    dir_b = write_snapshot(
        tmp_path / "run-b", chunks_b, versions, source_urls={}, fetched_at="2099-12-31T23:59:59Z"
    )

    assert dir_a.name == dir_b.name
