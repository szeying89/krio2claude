"""Ties CRI workbook parsing, the heuristic ATT&CK bridge, and snapshotting
together — the CRI-side counterpart to app/services/kb/refresh_service.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import IO

from app.services.cri.snapshot import write_snapshot
from app.services.cri.workbook_parser import parse_workbook
from app.services.kb.heuristic_mapping import HeuristicSource, infer_technique_mappings
from app.services.kb.snapshot import read_techniques


class CRIIngestionService:
    def __init__(self, cri_dir: Path) -> None:
        self.cri_dir = cri_dir

    def ingest(
        self,
        source: str | Path | IO[bytes],
        source_filename: str,
        fetched_at: str,
        kb_snapshot_dir: Path | None = None,
    ) -> Path:
        catalog = parse_workbook(source)

        inferred = {}
        kb_content_hash = None
        if kb_snapshot_dir is not None:
            techniques = read_techniques(kb_snapshot_dir)
            sources = [
                HeuristicSource(
                    id=statement.profile_id,
                    name=statement.name,
                    text=" ".join(statement.subject_tags),
                )
                for statement in catalog.statements
            ]
            inferred = infer_technique_mappings(sources, techniques)
            kb_content_hash = kb_snapshot_dir.name

        return write_snapshot(
            self.cri_dir,
            catalog,
            source_filename,
            fetched_at,
            kb_content_hash=kb_content_hash,
            inferred_mappings=inferred,
        )
