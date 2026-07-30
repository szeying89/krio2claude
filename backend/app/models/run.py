import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import RunStatus, StageStatus


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    status: Mapped[RunStatus] = mapped_column(
        SAEnum(RunStatus, native_enum=False, length=32, values_callable=lambda e: [m.value for m in e]),
        default=RunStatus.QUEUED,
        nullable=False,
    )
    parent_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("runs.id"), nullable=True
    )
    project_name: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    stages: Mapped[list["RunStage"]] = relationship(
        back_populates="run", order_by="RunStage.sequence_index", cascade="all, delete-orphan"
    )


class RunStage(Base):
    __tablename__ = "run_stages"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id"), nullable=False)
    sequence_index: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[StageStatus] = mapped_column(
        SAEnum(StageStatus, native_enum=False, length=32, values_callable=lambda e: [m.value for m in e]),
        default=StageStatus.PENDING,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped[Run] = relationship(back_populates="stages")
