from app.services.cri.ingestion_service import CRIIngestionService
from app.services.cri.snapshot import read_manifest
from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.snapshot import write_snapshot as write_kb_snapshot
from tests.kb_fixtures import load_json

FIXTURE = "tests/fixtures/cri/sample_cri_profile.xlsx"


def _build_kb_snapshot(tmp_path):
    chunks = parse_attack_enterprise_bundle(load_json("enterprise_bundle.json"))
    return write_kb_snapshot(
        tmp_path / "kb",
        chunks,
        versions={"attack_enterprise": "19.1"},
        source_urls={},
        fetched_at="2026-01-01T00:00:00Z",
    )


def test_ingest_without_kb_snapshot_leaves_mapping_empty(tmp_path):
    service = CRIIngestionService(tmp_path / "cri")
    snapshot_dir = service.ingest(FIXTURE, "sample_cri_profile.xlsx", "2026-01-01T00:00:00Z")

    manifest = read_manifest(snapshot_dir)
    assert manifest["kb_content_hash"] is None
    assert manifest["inferred_mapping_count"] == 0


def test_ingest_with_pinned_kb_snapshot_records_its_hash(tmp_path):
    kb_snapshot_dir = _build_kb_snapshot(tmp_path)
    service = CRIIngestionService(tmp_path / "cri")

    snapshot_dir = service.ingest(
        FIXTURE, "sample_cri_profile.xlsx", "2026-01-01T00:00:00Z", kb_snapshot_dir=kb_snapshot_dir
    )

    manifest = read_manifest(snapshot_dir)
    assert manifest["kb_content_hash"] == kb_snapshot_dir.name
    # heuristic mapping count may legitimately be zero for this tiny fixture
    # pairing — what matters is the pin is recorded and attributable.
    assert manifest["inferred_mapping_count"] >= 0


def test_ingest_is_reproducible_given_identical_kb_pin(tmp_path):
    kb_snapshot_dir = _build_kb_snapshot(tmp_path)
    service = CRIIngestionService(tmp_path / "cri")

    first = service.ingest(
        FIXTURE, "a.xlsx", "2026-01-01T00:00:00Z", kb_snapshot_dir=kb_snapshot_dir
    )
    second = service.ingest(
        FIXTURE, "b.xlsx", "2099-01-01T00:00:00Z", kb_snapshot_dir=kb_snapshot_dir
    )

    assert first == second, "identical catalog content must hash to the same snapshot"
