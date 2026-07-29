"""Task 21's review queue persistence: `ReviewItemRecord` (one per
surfaced critique finding, requiring human accept/reject) plus an
append-only `ReviewAuditEntry` log — "every decision is audited" means a
queryable trail per item, not just an overwritten status field.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ReviewItemRecord(Base):
    __tablename__ = "review_items"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    project_id: Mapped[str] = mapped_column(String, ForeignKey("projects.id"), nullable=False)
    revision_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("threat_model_revisions.id"), nullable=True
    )
    category: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    rationale: Mapped[str] = mapped_column(String, nullable=False)
    cited_element_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cited_statement_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="pending", nullable=False)
    decision_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ReviewAuditEntry(Base):
    __tablename__ = "review_audit_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    review_item_id: Mapped[str] = mapped_column(String, ForeignKey("review_items.id"), nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)  # "created" | "accepted" | "rejected"
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
