"""Task 19's "run revision" persistence. Deliberately a new, dedicated
table rather than a retrofit of `Run`/`RunStage` (Task 1): those model a
generic job-lifecycle skeleton (queued/running/complete, SSE-published
stages) keyed by a free-string `project_name`, with `parent_run_id`
reserved for a revision concept but never actually wired into any
pipeline — retrofitting it now would mean adding project-id linkage and
threat-model-specific fields to a shipped, tested model built for a
different, more generic purpose. `ThreatModelRevision` is the actual
project-scoped, diffable snapshot chain Task 19 needs; `Run` remains
available, unmodified, for whatever later task actually needs generic
job-lifecycle tracking.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ThreatModelRevision(Base):
    __tablename__ = "threat_model_revisions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String, ForeignKey("projects.id"), nullable=False)
    parent_revision_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("threat_model_revisions.id"), nullable=True
    )
    system_model_version: Mapped[int] = mapped_column(Integer, nullable=False)
    kb_snapshot_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    cri_snapshot_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    intel_article_hashes: Mapped[list[str]] = mapped_column(JSON, default=list)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
