"""Task 24: read access to the append-only audit log. There is
deliberately no write/delete endpoint here -- every entry is written by
the service call sites that actually perform a mutating action (KB
refresh, CRI upload, tiering answers, intel ingestion, model freezes,
exports, agent invocations), never by a client request to this router."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_audit_log_service
from app.services.audit.service import AuditLogService

router = APIRouter(tags=["audit"])


class AuditLogEntryOut(BaseModel):
    id: str
    at: datetime
    action: str
    project_id: str | None
    summary: str
    detail: dict[str, Any]


@router.get("/audit-log", response_model=list[AuditLogEntryOut])
async def list_audit_log(
    action_prefix: str | None = None,
    limit: int = 200,
    service: AuditLogService = Depends(get_audit_log_service),
) -> list[AuditLogEntryOut]:
    entries = await service.list_entries(action_prefix=action_prefix, limit=limit)
    return [AuditLogEntryOut.model_validate(e, from_attributes=True) for e in entries]


@router.get("/projects/{project_id}/audit-log", response_model=list[AuditLogEntryOut])
async def list_project_audit_log(
    project_id: str,
    action_prefix: str | None = None,
    limit: int = 200,
    service: AuditLogService = Depends(get_audit_log_service),
) -> list[AuditLogEntryOut]:
    entries = await service.list_entries(
        project_id=project_id, action_prefix=action_prefix, limit=limit
    )
    return [AuditLogEntryOut.model_validate(e, from_attributes=True) for e in entries]
