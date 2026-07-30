"""Task 24: the general-purpose, append-only audit log covering every
mutating action the plan names except review decisions (which already
have their own dedicated, real, append-only trail — `ReviewAuditEntry`,
Task 21 — referenced rather than duplicated here): agent invocations, KB
and CRI refreshes, tiering answers, intel ingestion, model freezes, and
exports.

Append-only by construction: `AuditLogService` (app/services/audit/
service.py) exposes only `record` (insert) and `list_entries` (read) --
there is no update or delete method, and nothing in this module defines
one.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditLogEntry(Base):
    __tablename__ = "audit_log_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    action: Mapped[str] = mapped_column(String, nullable=False)
    project_id: Mapped[str | None] = mapped_column(String, nullable=True)
    summary: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
