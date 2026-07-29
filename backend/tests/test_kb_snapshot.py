import json

from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.capec import parse_capec_bundle
from app.services.kb.d3fend import parse_d3fend_mappings
from app.services.kb.models import TechniqueChunk
from app.services.kb.snapshot import (
    compute_content_hash,
    merge_relationships,
    read_manifest,
    read_techniques,
    write_snapshot,
)
from tests.kb_fixtures import load_json


def _load_enterprise_chunks() -> list[TechniqueChunk]:
    return parse_attack_enterprise_bundle(load_json("enterprise_bundle.json"))


def test_merge_relationships_attaches_capec_and_d3fend_to_known_techniques():
    chunks = _load_enterprise_chunks()
    capec_map = parse_capec_bundle(load_json("capec_bundle.json"))
    d3fend_map = parse_d3fend_mappings(load_json("d3fend_mappings.json"))

    merged, _unresolved_capec, _unresolved_d3fend = merge_relationships(
        chunks, capec_map, d3fend_map
    )
    by_id = {c.id: c for c in merged}

    assert by_id["T1190"].relationships["capec"] == ("CAPEC-66",)
    assert by_id["T1190"].relationships["d3fend"] == ("D3-AI", "D3-NM")
    assert by_id["T1071"].relationships["capec"] == ("CAPEC-94",)
    assert by_id["T1071"].relationships["d3fend"] == ("D3-NTA",)
    assert by_id["T1055.011"].relationships == {}


def test_merge_relationships_reports_unresolved_mappings_visibly():
    chunks = _load_enterprise_chunks()
    capec_map = parse_capec_bundle(load_json("capec_bundle.json"))
    d3fend_map = parse_d3fend_mappings(load_json("d3fend_mappings.json"))

    _, unresolved_capec, unresolved_d3fend = merge_relationships(chunks, capec_map, d3fend_map)

    # CAPEC-94 maps to both T1071 (known) and T9999-unknown (not in the KB);
    # the unknown side must be visible, not silently merged into T1071's entry.
    assert unresolved_capec == ["CAPEC-94"]
    assert unresolved_d3fend == ["D3-DNSAL"]


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

    snapshot_dir = write_snapshot(
        tmp_path, chunks, versions, source_urls={"attack_enterprise": "https://example/x"},
        fetched_at="2026-01-01T00:00:00Z",
    )

    assert snapshot_dir.is_dir()
    assert not any(p.name.startswith(".tmp-") for p in tmp_path.iterdir())

    manifest = read_manifest(snapshot_dir)
    assert manifest["versions"] == versions
    assert manifest["chunk_counts"] == {"enterprise": 3}

    read_back = read_techniques(snapshot_dir)
    assert {c.id for c in read_back} == {c.id for c in chunks}


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
    chunks_b = parse_attack_enterprise_bundle(json.loads(json.dumps(load_json("enterprise_bundle.json"))))
    versions = {"attack_enterprise": "19.1"}

    dir_a = write_snapshot(
        tmp_path / "run-a", chunks_a, versions, source_urls={}, fetched_at="2026-01-01T00:00:00Z"
    )
    dir_b = write_snapshot(
        tmp_path / "run-b", chunks_b, versions, source_urls={}, fetched_at="2099-12-31T23:59:59Z"
    )

    assert dir_a.name == dir_b.name
