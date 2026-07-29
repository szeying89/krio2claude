import argparse
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.assurance import router as assurance_router
from app.api.cri import router as cri_router
from app.api.cri import snapshots_router as cri_snapshots_router
from app.api.enumeration import router as enumeration_router
from app.api.intel import router as intel_router
from app.api.kb import router as kb_router
from app.api.mermaid import router as mermaid_router
from app.api.mitigation import router as mitigation_router
from app.api.modelbuilding import router as modelbuilding_router
from app.api.projects import router as projects_router
from app.api.retrieval import router as retrieval_router
from app.api.review import router as review_router
from app.api.revisions import router as revisions_router
from app.api.risk import router as risk_router
from app.api.runs import router as runs_router
from app.api.systemmodel import router as systemmodel_router
from app.core.config import assert_bind_allowed, get_settings
from app.db.base import get_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.runs_dir.mkdir(parents=True, exist_ok=True)
    settings.projects_dir.mkdir(parents=True, exist_ok=True)
    settings.kb_dir.mkdir(parents=True, exist_ok=True)
    settings.cri_dir.mkdir(parents=True, exist_ok=True)
    settings.intel_dir.mkdir(parents=True, exist_ok=True)
    db = get_database()
    await db.create_all()
    yield
    await db.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="Ground-Truth Threat Modelling Platform", lifespan=lifespan)
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
