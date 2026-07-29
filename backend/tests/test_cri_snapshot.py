from app.services.cri.snapshot import compute_content_hash, read_manifest, write_snapshot
from app.services.cri.workbook_parser import parse_workbook

FIXTURE = "tests/fixtures/cri/sample_cri_profile.xlsx"


def _load_catalog():
    return parse_workbook(FIXTURE)


def test_content_hash_is_deterministic():
    catalog = _load_catalog()
    assert compute_content_hash(catalog) == compute_content_hash(catalog)


def test_content_hash_changes_with_different_catalog():
    catalog_a = _load_catalog()
    catalog_b = _load_catalog()
    # mutate one statement's text to produce a genuinely different catalog
    import dataclasses

    mutated_statements = list(catalog_b.statements)
    mutated_statements[0] = dataclasses.replace(mutated_statements[0], text="different text")
    catalog_b = dataclasses.replace(catalog_b, statements=tuple(mutated_statements))

    assert compute_content_hash(catalog_a) != compute_content_hash(catalog_b)


def test_write_snapshot_atomic_and_readable(tmp_path):
    catalog = _load_catalog()
    snapshot_dir = write_snapshot(
        tmp_path, catalog, "sample_cri_profile.xlsx", fetched_at="2026-01-01T00:00:00Z"
    )

    assert snapshot_dir.is_dir()
    assert not any(p.name.startswith(".tmp-") for p in tmp_path.iterdir())

    manifest = read_manifest(snapshot_dir)
    assert manifest["statement_count"] == 3
    assert manifest["tier_counts"] == {"1": 3, "2": 2, "3": 1, "4": 1}
    assert manifest["unresolved_regulatory_references"] == ["TESTREG-UNKNOWN"]
    assert manifest["kb_content_hash"] is None
    assert manifest["inferred_mapping_count"] == 0

    statements_json = (snapshot_dir / "statements.json").read_text()
    assert "GV.OC-01.01" in statements_json


def test_rerunning_write_snapshot_is_a_noop(tmp_path):
    catalog = _load_catalog()
    first = write_snapshot(tmp_path, catalog, "x.xlsx", fetched_at="2026-01-01T00:00:00Z")
    first_mtime = (first / "manifest.json").stat().st_mtime_ns

    second = write_snapshot(tmp_path, catalog, "x.xlsx", fetched_at="2099-01-01T00:00:00Z")

    assert second == first
    assert (second / "manifest.json").stat().st_mtime_ns == first_mtime


def test_rerun_with_a_new_kb_pin_updates_mapping_metadata_only(tmp_path):
    """The catalog itself is content-addressed and immutable, but the
    heuristic KB mapping is metadata about a (catalog, KB snapshot) pairing
    — re-ingesting the same unchanged catalog against a newly available (or
    different) KB snapshot must still refresh the mapping fields in place,
    without touching the catalog's own immutable files."""
    catalog = _load_catalog()
    first = write_snapshot(tmp_path, catalog, "x.xlsx", fetched_at="2026-01-01T00:00:00Z")
    assert read_manifest(first)["kb_content_hash"] is None
    statements_mtime = (first / "statements.json").stat().st_mtime_ns

    from app.services.kb.heuristic_mapping import InferredMapping

    second = write_snapshot(
        tmp_path,
        catalog,
        "x.xlsx",
        fetched_at="2099-01-01T00:00:00Z",
        kb_content_hash="some-kb-hash",
        inferred_mappings={"GV.OC-01.01": [InferredMapping("T1190", ("test",))]},
    )

    assert second == first
    manifest = read_manifest(second)
    assert manifest["kb_content_hash"] == "some-kb-hash"
    assert manifest["inferred_mapping_count"] == 1
    # the catalog's own files are untouched by a mapping-only refresh
    assert (second / "statements.json").stat().st_mtime_ns == statements_mtime
    second_manifest_mtime = (second / "manifest.json").stat().st_mtime_ns

    third = write_snapshot(
        tmp_path,
        catalog,
        "x.xlsx",
        fetched_at="2100-01-01T00:00:00Z",
        kb_content_hash="some-kb-hash",
        inferred_mappings={"GV.OC-01.01": [InferredMapping("T1190", ("test",))]},
    )
    # same catalog, same kb pin as `second`: now a true no-op
    assert (third / "manifest.json").stat().st_mtime_ns == second_manifest_mtime
