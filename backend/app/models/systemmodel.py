import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SystemModelVersion(Base):
    """A frozen, immutable `SystemModel` snapshot for a project. Stored as
    its own OTM document (`app.services.systemmodel.otm.to_otm`/`from_otm`
    is the (de)serializer) so the persistence format is exactly the same
    thing a user would export — no separate ad hoc schema to keep in sync.
    """

    __tablename__ = "system_model_versions"
    __table_args__ = (UniqueConstraint("project_id", "version", name="uq_system_model_version"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    otm_document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
