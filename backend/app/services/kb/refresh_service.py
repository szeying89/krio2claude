"""Orchestrates fetch -> parse -> snapshot for a KB refresh.

Fetchers are injectable so tests can supply fixture-returning callables
instead of real network calls (see tests/test_kb_refresh_service.py) — the
default fetchers (app/services/kb/fetchers.py) are only used in production.

All four sources are fetched and parsed *before* anything is written to
disk, so a failure partway through (a network error, a malformed source)
never leaves a partial snapshot behind — see the "partial download
publishes nothing" test.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from app.services.kb import fetchers as default_fetchers
from app.services.kb.atlas import parse_atlas_data
from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.capec import parse_capec_bundle
from app.services.kb.d3fend import parse_d3fend_csv
from app.services.kb.heuristic_mapping import HeuristicSource, infer_technique_mappings
from app.services.kb.snapshot import merge_relationships, write_snapshot

FetchResult = tuple[object, str, str]
Fetcher = Callable[[], FetchResult]


class KBRefreshService:
    def __init__(
        self,
        kb_dir: Path,
        fetch_attack_enterprise: Fetcher | None = None,
        fetch_atlas: Fetcher | None = None,
        fetch_capec: Fetcher | None = None,
        fetch_d3fend: Fetcher | None = None,
    ) -> None:
        self.kb_dir = kb_dir
        self.fetch_attack_enterprise = fetch_attack_enterprise or default_fetchers.fetch_attack_enterprise
        self.fetch_atlas = fetch_atlas or default_fetchers.fetch_atlas
        self.fetch_capec = fetch_capec or default_fetchers.fetch_capec
        self.fetch_d3fend = fetch_d3fend or default_fetchers.fetch_d3fend

    def refresh(self) -> Path:
        enterprise_bundle, enterprise_version, enterprise_url = self.fetch_attack_enterprise()
        atlas_data, atlas_version, atlas_url = self.fetch_atlas()
        capec_bundle, capec_version, capec_url = self.fetch_capec()
        d3fend_csv_text, d3fend_version, d3fend_url = self.fetch_d3fend()

        enterprise_chunks = parse_attack_enterprise_bundle(enterprise_bundle)  # type: ignore[arg-type]
        atlas_chunks = parse_atlas_data(atlas_data)  # type: ignore[arg-type]
        capec_map = parse_capec_bundle(capec_bundle)  # type: ignore[arg-type]
        d3fend_catalog = parse_d3fend_csv(d3fend_csv_text)  # type: ignore[arg-type]

        chunks = enterprise_chunks + atlas_chunks

        # D3FEND's real export carries no ATT&CK mapping (see d3fend.py), so
        # the bridge is a heuristic (lexical-overlap) inference rather than
        # an authoritative source — every result is tagged accordingly.
        d3fend_sources = [
            HeuristicSource(id=t.id, name=t.name, text=t.definition) for t in d3fend_catalog
        ]
        d3fend_inferred = infer_technique_mappings(d3fend_sources, chunks)

        merged, unresolved_capec = merge_relationships(chunks, capec_map, d3fend_inferred)

        versions = {
            "attack_enterprise": enterprise_version,
            "atlas": atlas_version,
            "capec": capec_version,
            "d3fend": d3fend_version,
        }
        source_urls = {
            "attack_enterprise": enterprise_url,
            "atlas": atlas_url,
            "capec": capec_url,
            "d3fend": d3fend_url,
        }

        return write_snapshot(
            self.kb_dir,
            merged,
            versions,
            source_urls,
            fetched_at=datetime.now(UTC).isoformat(),
            unresolved_capec=unresolved_capec,
            d3fend_catalog=d3fend_catalog,
            d3fend_inferred=d3fend_inferred,
        )
