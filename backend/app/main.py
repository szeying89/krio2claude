import argparse
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.assurance import router as assurance_router
from app.api.audit import router as audit_router
from app.api.auth import require_api_key
from app.api.body_size_limit import BodySizeLimitMiddleware
from app.api.cri import router as cri_router
from app.api.cri import snapshots_router as cri_snapshots_router
from app.api.enumeration import router as enumeration_router
from app.api.intel import router as intel_router
from app.api.kb import router as kb_router
from app.api.mermaid import router as mermaid_router
from app.api.mitigation import router as mitigation_router
from app.api.modelbuilding import router as modelbuilding_router
from app.api.projects import router as projects_router
from app.api.reports import router as reports_router
from app.api.retrieval import router as retrieval_router
from app.api.review import router as review_router
from app.api.revisions import router as revisions_router
from app.api.risk import router as risk_router
from app.api.runs import router as runs_router
from app.api.systemmodel import router as systemmodel_router
from app.core.config import assert_bind_allowed, get_settings
from app.db.base import get_database
from app.services.fs_permissions import secure_mkdir
from app.services.sqlite_path import sqlite_db_path


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    secure_mkdir(settings.data_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.runs_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.projects_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.kb_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.cri_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.intel_dir, parents=True, exist_ok=True)
    secure_mkdir(settings.cache_dir, parents=True, exist_ok=True)
    db = get_database()
    await db.create_all()
    db_path = sqlite_db_path(settings.database_url)
    if db_path is not None and db_path.exists():
        db_path.chmod(0o600)
    yield
    await db.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    # Security-review finding: FastAPI's own docs routes (/docs, /redoc,
    # /openapi.json) are plain Starlette routes added in setup(), added
    # outside the dependency-injection tree entirely -- the app-level
    # `dependencies=[Depends(require_api_key)]` below can never reach them
    # (confirmed: every other route has a populated `.dependant`, these do
    # not). Once an operator actually turns the gate on, leaving the full
    # API schema reachable by anyone defeats the point of enabling it, so
    # disable them rather than leave them unauthenticated.
    docs_enabled = settings.api_key is None
    app = FastAPI(
        title="Ground-Truth Threat Modelling Platform",
        lifespan=lifespan,
        dependencies=[Depends(require_api_key)],
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,  # no cookie-based auth -- nothing to carry cross-origin
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["content-type", "x-api-key"],
    )
    # Security-review finding: only file-upload endpoints had a body-size
    # cap. Added last so it wraps outermost -- an oversized body is
    # rejected before CORS handling or any route/dependency ever runs.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.include_router(runs_router)
    app.include_router(projects_router)
    app.include_router(kb_router)
    app.include_router(cri_router)
    app.include_router(cri_snapshots_router)
    app.include_router(retrieval_router)
    app.include_router(mermaid_router)
    app.include_router(modelbuilding_router)
    app.include_router(systemmodel_router)
    app.include_router(enumeration_router)
    app.include_router(mitigation_router)
    app.include_router(risk_router)
    app.include_router(intel_router)
    app.include_router(revisions_router)
    app.include_router(assurance_router)
    app.include_router(review_router)
    app.include_router(reports_router)
    app.include_router(audit_router)
    return app


app = create_app()


def run() -> None:
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--allow-non-loopback", action="store_true")
    args = parser.parse_args()

    settings = get_settings()
    host = args.host or settings.host
    allow_non_loopback = args.allow_non_loopback or settings.allow_non_loopback

    assert_bind_allowed(host, allow_non_loopback)

    uvicorn.run(app, host=host, port=args.port or settings.port)


if __name__ == "__main__":
    run()
