import asyncio

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_audit_log_service, get_kb_refresh_service
from app.core.config import get_settings
from app.services.audit.service import AuditLogService
from app.services.kb.refresh_service import KBRefreshService
from app.services.kb.snapshot import read_manifest

router = APIRouter(prefix="/kb", tags=["kb"])


@router.post("/refresh")
async def refresh_kb(
    service: KBRefreshService = Depends(get_kb_refresh_service),
    audit: AuditLogService = Depends(get_audit_log_service),
) -> dict:
    try:
        snapshot_dir = await asyncio.to_thread(service.refresh)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"KB refresh failed: {exc}") from exc
    manifest = read_manifest(snapshot_dir)
    await audit.record(
        "kb.refresh",
        f"KB snapshot {snapshot_dir.name} fetched",
        detail={"content_hash": snapshot_dir.name, "fetched_at": manifest.get("fetched_at")},
    )
    return manifest


@router.get("/snapshots")
async def list_snapshots() -> list[dict]:
    kb_dir = get_settings().kb_dir
    if not kb_dir.exists():
        return []
    manifests = []
    for entry in kb_dir.iterdir():
        if not entry.is_dir() or entry.name.startswith(".tmp-"):
            continue
        manifests.append(read_manifest(entry))
    manifests.sort(key=lambda m: m["fetched_at"], reverse=True)
    return manifests


@router.get("/snapshots/{content_hash}")
async def get_snapshot(content_hash: str) -> dict:
    snapshot_dir = get_settings().kb_dir / content_hash
    if not snapshot_dir.is_dir():
        raise HTTPException(status_code=404, detail="snapshot not found")
    return read_manifest(snapshot_dir)
