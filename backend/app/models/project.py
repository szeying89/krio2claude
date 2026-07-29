import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import BusinessCriticality, SystemClass


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    business_criticality: Mapped[BusinessCriticality] = mapped_column(
        SAEnum(
            BusinessCriticality,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    system_class: Mapped[SystemClass] = mapped_column(
        SAEnum(
            SystemClass,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    data_classifications: Mapped[list[str]] = mapped_column(JSON, default=list)
    compliance_regimes: Mapped[list[str]] = mapped_column(JSON, default=list)
    scope_statements: Mapped[list[str]] = mapped_column(JSON, default=list)
    declared_controls: Mapped[list[str]] = mapped_column(JSON, default=list)

    cri_snapshot_hash: Mapped[str | None] = mapped_column(String, nullable=True)

    # Task 11: Enterprise is always active; ATLAS is off unless a user has
    # explicitly confirmed it — via declaration or via confirming the
    # rule-based detector's proposal. Never flipped by the detector itself.
    atlas_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    documents: Mapped[list["DesignDocument"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    impact_tiering: Mapped["ImpactTiering | None"] = relationship(
        back_populates="project", cascade="all, delete-orphan", uselist=False
    )


class DesignDocument(Base):
    __tablename__ = "design_documents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)

    filename: Mapped[str] = mapped_column(String, nullable=False)
    content_type: Mapped[str] = mapped_column(String, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_path: Mapped[str] = mapped_column(String, nullable=False)

    extracted_prose: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mermaid_blocks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    project: Mapped[Project] = relationship(back_populates="documents")


class ImpactTiering(Base):
    __tablename__ = "impact_tiering"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), primary_key=True)
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    triggering_question_id: Mapped[str | None] = mapped_column(String, nullable=True)
    answers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    project: Mapped[Project] = relationship(back_populates="impact_tiering")
