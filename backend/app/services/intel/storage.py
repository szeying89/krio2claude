"""Content-addressed, immutable article storage (Task 18) — mirrors
`app/services/kb/snapshot.py`'s pattern exactly: temp-dir-then-rename so a
failure never publishes a partial write, content hash covers only the
verbatim article text (never fetch timestamps), and re-ingesting
identical content is a true no-op.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArticleRecord:
    content_hash: str
    source_url: str | None
    fetched_at: str
    raw_text: str


def compute_content_hash(raw_text: str) -> str:
    return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()


def write_article(
    intel_dir: Path, raw_text: str, source_url: str | None, fetched_at: str
) -> Path:
    content_hash = compute_content_hash(raw_text)
    article_dir = intel_dir / content_hash
    if article_dir.exists():
        return article_dir  # verbatim content already stored: a true no-op

    intel_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = intel_dir / f".tmp-{content_hash}-{uuid.uuid4().hex}"
    tmp_dir.mkdir(parents=True)
    (tmp_dir / "article.txt").write_text(raw_text)
    manifest: dict[str, Any] = {
        "content_hash": content_hash,
        "source_url": source_url,
        "fetched_at": fetched_at,
    }
    (tmp_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    tmp_dir.rename(article_dir)
    return article_dir


def read_article(article_dir: Path) -> ArticleRecord:
    manifest = json.loads((article_dir / "manifest.json").read_text())
    raw_text = (article_dir / "article.txt").read_text()
    return ArticleRecord(
        content_hash=manifest["content_hash"],
        source_url=manifest["source_url"],
        fetched_at=manifest["fetched_at"],
        raw_text=raw_text,
    )


def article_exists(intel_dir: Path, content_hash: str) -> bool:
    return (intel_dir / content_hash).exists()


def write_extraction(
    article_dir: Path,
    extracted: dict[str, Any],
    injection_indicators: tuple[str, ...],
) -> None:
    """The LLM extraction is metadata *about* the immutable article, not
    part of its own verbatim content — stored as a sibling file inside the
    same content-addressed directory, written once at ingestion time so a
    later read never needs to re-invoke the LLM."""
    payload = {"extracted_intel": extracted, "injection_indicators": list(injection_indicators)}
    (article_dir / "extraction.json").write_text(json.dumps(payload, indent=2, sort_keys=True))


def read_extraction(article_dir: Path) -> dict[str, Any] | None:
    path = article_dir / "extraction.json"
    if not path.exists():
        return None
    data: dict[str, Any] = json.loads(path.read_text())
    return data
