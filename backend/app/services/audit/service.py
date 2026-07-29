"""Task 24's general-purpose audit log service. Append-only: this class
exposes exactly two operations, `record` (insert) and `list_entries`
(read) -- there is no update or delete, so nothing that calls this
service can rewrite history.

Every free-text field is redacted before it is ever written to the
database, mirroring the LLM gateway's own pre-send redaction (Task 7,
turned on by default in Task 24 -- see app/api/deps.py). An audit log
that could itself leak a credential pasted into a filename or an
uploaded document would defeat its own purpose.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLogEntry
from app.services.llm.redaction import redact_secrets


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value).redacted_text
    return value


class AuditLogService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        action: str,
        summary: str,
        project_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            action=action,
            project_id=project_id,
            summary=_redact(summary),
            detail={key: _redact(value) for key, value in (detail or {}).items()},
        )
        self.session.add(entry)
        await self.session.commit()
        await self.session.refresh(entry)
        return entry

    async def list_entries(
        self, project_id: str | None = None, action_prefix: str | None = None, limit: int = 200
    ) -> list[AuditLogEntry]:
        query = select(AuditLogEntry).order_by(AuditLogEntry.at.desc()).limit(limit)
        if project_id is not None:
            query = query.where(AuditLogEntry.project_id == project_id)
        if action_prefix is not None:
            query = query.where(AuditLogEntry.action.like(f"{action_prefix}%"))
        result = await self.session.execute(query)
        return list(result.scalars().all())
