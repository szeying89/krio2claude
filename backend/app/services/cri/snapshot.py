"""Immutable, content-hashed CRI catalog snapshot writer.

Mirrors app/services/kb/snapshot.py's pattern: the content hash covers only
normalized catalog data (never fetch timestamps), snapshots are written via
a temp-dir-then-rename so a failure never publishes a partial snapshot, and
re-running against unchanged data *with the same KB pin* is a no-op. CRI
snapshots live in their own namespace (./data/cri/<content_hash>/), separate
from the MITRE KB, because refresh cadence, provenance, and licensing
differ — CRI content is user-supplied and never redistributed.

The heuristic CRI->ATT&CK bridge (see app/services/kb/heuristic_mapping.py)
is metadata *about* a (catalog, KB snapshot) pairing, not part of the
catalog's own immutable content — the same catalog can legitimately be
re-evaluated against a newer KB snapshot without the catalog itself having
changed. So while `statements.json`/`regulatory_documents.json`/
`eee_packages.json` are written once and never touched again, re-ingesting
an unchanged catalog against a *different* kb_content_hash still refreshes
`inferred_mappings.json` and the manifest's mapping fields in place.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.services.cri.models import ControlObjectiveCatalog
from app.services.kb.heuristic_mapping import InferredMapping


def compute_content_hash(catalog: ControlObjectiveCatalog) -> str:
    payload = {
        "version": catalog.version,
        "statements": [s.to_dict() for s in sorted(catalog.statements, key=lambda s: s.profile_id)],
        "regulatory_documents": {
            code: asdict(doc) for code, doc in sorted(catalog.regulatory_documents.items())
        },
        "eee_packages": {pid: asdict(pkg) for pid, pkg in sorted(catalog.eee_packages.items())},
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _mapping_manifest_fields(
    kb_content_hash: str | None, inferred_mappings: dict[str, list[InferredMapping]]
) -> dict[str, Any]:
    return {
        "kb_content_hash": kb_content_hash,
        "inferred_mapping_statement_count": len(inferred_mappings),
        "inferred_mapping_count": sum(len(v) for v in inferred_mappings.values()),
    }


def _write_inferred_mappings(
    directory: Path, inferred_mappings: dict[str, list[InferredMapping]]
) -> None:
    (directory / "inferred_mappings.json").write_text(
        json.dumps(
            {
                profile_id: [
                    {"technique_id": m.technique_id, "matched_terms": list(m.matched_terms)}
                    for m in mappings
                ]
                for profile_id, mappings in sorted(inferred_mappings.items())
            },
            indent=2,
            sort_keys=True,
        )
    )


def write_snapshot(
    cri_dir: Path,
    catalog: ControlObjectiveCatalog,
    source_filename: str,
    fetched_at: str,
    kb_content_hash: str | None = None,
    inferred_mappings: dict[str, list[InferredMapping]] | None = None,
) -> Path:
    inferred_mappings = inferred_mappings or {}
    content_hash = compute_content_hash(catalog)
    snapshot_dir = cri_dir / content_hash

    if snapshot_dir.exists():
        existing_manifest = read_manifest(snapshot_dir)
        if existing_manifest.get("kb_content_hash") == kb_content_hash:
            return snapshot_dir  # unchanged catalog, unchanged KB pin: a true no-op

        # Same catalog content, but re-evaluated against a different (or
        # newly available) KB snapshot: refresh only the mapping-derived
        # metadata, leaving the immutable catalog files untouched.
        _write_inferred_mappings(snapshot_dir, inferred_mappings)
        existing_manifest.update(_mapping_manifest_fields(kb_content_hash, inferred_mappings))
        (snapshot_dir / "manifest.json").write_text(
            json.dumps(existing_manifest, indent=2, sort_keys=True)
        )
        return snapshot_dir

    cri_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = cri_dir / f".tmp-{content_hash}-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True)

    sorted_statements = sorted(catalog.statements, key=lambda s: s.profile_id)
    (tmp_dir / "statements.json").write_text(
        json.dumps([s.to_dict() for s in sorted_statements], indent=2, sort_keys=True)
    )
    (tmp_dir / "regulatory_documents.json").write_text(
        json.dumps(
            {code: asdict(doc) for code, doc in sorted(catalog.regulatory_documents.items())},
            indent=2,
            sort_keys=True,
        )
    )
    (tmp_dir / "eee_packages.json").write_text(
        json.dumps(
            {pid: asdict(pkg) for pid, pkg in sorted(catalog.eee_packages.items())},
            indent=2,
            sort_keys=True,
        )
    )
    _write_inferred_mappings(tmp_dir, inferred_mappings)

    tier_counts = {str(tier): len(catalog.statements_for_tier(tier)) for tier in (1, 2, 3, 4)}

    manifest: dict[str, Any] = {
        "content_hash": content_hash,
        "version": catalog.version,
        "fetched_at": fetched_at,
        "source_filename": source_filename,
        "statement_count": len(catalog.statements),
        "tier_counts": tier_counts,
        "regulatory_document_count": len(catalog.regulatory_documents),
        "eee_package_count": len(catalog.eee_packages),
        "unresolved_regulatory_references": sorted(catalog.unresolved_regulatory_references),
        **_mapping_manifest_fields(kb_content_hash, inferred_mappings),
    }
    (tmp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    tmp_dir.rename(snapshot_dir)
    return snapshot_dir


def read_manifest(snapshot_dir: Path) -> dict[str, Any]:
    return json.loads((snapshot_dir / "manifest.json").read_text())
