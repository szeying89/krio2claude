"""Immutable, content-hashed KB snapshot writer.

The content hash is computed purely from the normalized technique data and
upstream version identifiers — never from fetch timestamps — so that
identical upstream fixtures always produce an identical snapshot hash, and
re-running a refresh against unchanged upstream data is a no-op (the
snapshot directory already exists).

Snapshots are written to a temp directory and published via an atomic
rename, so a failure partway through never leaves a partial snapshot
directory behind.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.heuristic_mapping import InferredMapping
from app.services.kb.models import TechniqueChunk


def merge_relationships(
    chunks: list[TechniqueChunk],
    capec_map: dict[str, list[str]],
    d3fend_inferred: dict[str, list[InferredMapping]] | None = None,
) -> tuple[list[TechniqueChunk], list[str]]:
    """Attach relationships to techniques that exist in the loaded KB.

    - `capec_map` is authoritative (technique_id -> [capec_id, ...], sourced
      from CAPEC's own STIX external_references). Mappings referencing a
      technique ID absent from the KB are never silently dropped — they're
      returned separately so the snapshot manifest can report them.
    - `d3fend_inferred` is a heuristic bridge (see heuristic_mapping.py),
      keyed by D3FEND technique ID, each value a list of InferredMapping
      pointing at technique_ids that — by construction — are always in the
      loaded KB (the matcher only ever matches against provided techniques),
      so there is no "unresolved" concept for it. Stored under
      relationships["d3fend_inferred"], kept distinct from a future
      relationships["d3fend"] key reserved for an authoritative mapping.
    """
    by_id = {chunk.id for chunk in chunks}

    technique_to_d3fend_ids: dict[str, set[str]] = {}
    for d3fend_id, mappings in (d3fend_inferred or {}).items():
        for mapping in mappings:
            technique_to_d3fend_ids.setdefault(mapping.technique_id, set()).add(d3fend_id)

    merged = []
    for chunk in chunks:
        relationships = dict(chunk.relationships)
        if chunk.id in capec_map:
            relationships["capec"] = tuple(sorted(set(capec_map[chunk.id])))
        if chunk.id in technique_to_d3fend_ids:
            relationships["d3fend_inferred"] = tuple(sorted(technique_to_d3fend_ids[chunk.id]))
        merged.append(dataclasses.replace(chunk, relationships=relationships))

    unresolved_capec = sorted(
        {capec_id for tid, ids in capec_map.items() if tid not in by_id for capec_id in ids}
    )
    return merged, unresolved_capec


def compute_content_hash(chunks: list[TechniqueChunk], versions: dict[str, str]) -> str:
    payload = {
        "techniques": [c.to_dict() for c in sorted(chunks, key=lambda c: (c.matrix, c.id))],
        "versions": dict(sorted(versions.items())),
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def write_snapshot(
    kb_dir: Path,
    chunks: list[TechniqueChunk],
    versions: dict[str, str],
    source_urls: dict[str, str],
    fetched_at: str,
    unresolved_capec: list[str] | None = None,
    d3fend_catalog: list[D3fendTechnique] | None = None,
    d3fend_inferred: dict[str, list[InferredMapping]] | None = None,
) -> Path:
    content_hash = compute_content_hash(chunks, versions)
    snapshot_dir = kb_dir / content_hash
    if snapshot_dir.exists():
        return snapshot_dir  # re-running against unchanged upstream data is a no-op

    kb_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = kb_dir / f".tmp-{content_hash}-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True)

    sorted_chunks = sorted(chunks, key=lambda c: (c.matrix, c.id))
    (tmp_dir / "techniques.json").write_text(
        json.dumps([c.to_dict() for c in sorted_chunks], indent=2, sort_keys=True)
    )

    d3fend_catalog = d3fend_catalog or []
    (tmp_dir / "d3fend_catalog.json").write_text(
        json.dumps(
            [dataclasses.asdict(t) for t in sorted(d3fend_catalog, key=lambda t: t.id)],
            indent=2,
            sort_keys=True,
        )
    )

    d3fend_inferred = d3fend_inferred or {}
    inferred_count = sum(len(v) for v in d3fend_inferred.values())
    (tmp_dir / "inferred_mappings.json").write_text(
        json.dumps(
            {
                "d3fend": {
                    source_id: [
                        {"technique_id": m.technique_id, "matched_terms": list(m.matched_terms)}
                        for m in mappings
                    ]
                    for source_id, mappings in sorted(d3fend_inferred.items())
                }
            },
            indent=2,
            sort_keys=True,
        )
    )

    chunk_counts: dict[str, int] = {}
    for chunk in sorted_chunks:
        chunk_counts[chunk.matrix] = chunk_counts.get(chunk.matrix, 0) + 1

    manifest: dict[str, Any] = {
        "content_hash": content_hash,
        "fetched_at": fetched_at,
        "versions": versions,
        "source_urls": source_urls,
        "chunk_counts": chunk_counts,
        "unresolved_capec_mappings": sorted(unresolved_capec or []),
        "d3fend_catalog_size": len(d3fend_catalog),
        "d3fend_inferred_mapping_count": inferred_count,
    }
    (tmp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    tmp_dir.rename(snapshot_dir)
    return snapshot_dir


def read_manifest(snapshot_dir: Path) -> dict[str, Any]:
    return json.loads((snapshot_dir / "manifest.json").read_text())


def latest_snapshot_dir(kb_dir: Path) -> Path | None:
    """The most recently fetched KB snapshot on disk, or None if none
    exists yet — shared by every consumer that needs "whatever the current
    KB is" (CRI ingestion's pinned mapping, the Task 11 CAPEC bridge)
    rather than each keeping its own copy of this lookup."""
    if not kb_dir.exists():
        return None
    candidates = [d for d in kb_dir.iterdir() if d.is_dir() and not d.name.startswith(".tmp-")]
    if not candidates:
        return None
    return max(candidates, key=lambda d: read_manifest(d)["fetched_at"])


def read_techniques(snapshot_dir: Path) -> list[TechniqueChunk]:
    data = json.loads((snapshot_dir / "techniques.json").read_text())
    return [TechniqueChunk.from_dict(d) for d in data]


def read_d3fend_catalog(snapshot_dir: Path) -> list[D3fendTechnique]:
    data = json.loads((snapshot_dir / "d3fend_catalog.json").read_text())
    return [D3fendTechnique(**d) for d in data]
