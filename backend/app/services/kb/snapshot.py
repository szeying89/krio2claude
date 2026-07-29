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

from app.services.kb.models import TechniqueChunk


def merge_relationships(
    chunks: list[TechniqueChunk],
    capec_map: dict[str, list[str]],
    d3fend_map: dict[str, list[str]],
) -> tuple[list[TechniqueChunk], list[str], list[str]]:
    """Attach CAPEC/D3FEND relationships to techniques that exist in the
    loaded KB. Mappings that reference a technique ID absent from the KB are
    never silently dropped without a trace — they're returned separately so
    the snapshot manifest can report them (mirrors the plan's
    cri_mapping_absent / mapping_inferred visibility principle)."""
    by_id = {chunk.id for chunk in chunks}

    merged = []
    for chunk in chunks:
        relationships = dict(chunk.relationships)
        if chunk.id in capec_map:
            relationships["capec"] = tuple(sorted(set(capec_map[chunk.id])))
        if chunk.id in d3fend_map:
            relationships["d3fend"] = tuple(sorted(set(d3fend_map[chunk.id])))
        merged.append(dataclasses.replace(chunk, relationships=relationships))

    unresolved_capec = sorted(
        {capec_id for tid, ids in capec_map.items() if tid not in by_id for capec_id in ids}
    )
    unresolved_d3fend = sorted(
        {d3fend_id for tid, ids in d3fend_map.items() if tid not in by_id for d3fend_id in ids}
    )
    return merged, unresolved_capec, unresolved_d3fend


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
    unresolved_d3fend: list[str] | None = None,
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
        "unresolved_d3fend_mappings": sorted(unresolved_d3fend or []),
    }
    (tmp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    tmp_dir.rename(snapshot_dir)
    return snapshot_dir


def read_manifest(snapshot_dir: Path) -> dict[str, Any]:
    return json.loads((snapshot_dir / "manifest.json").read_text())


def read_techniques(snapshot_dir: Path) -> list[TechniqueChunk]:
    data = json.loads((snapshot_dir / "techniques.json").read_text())
    return [TechniqueChunk.from_dict(d) for d in data]
