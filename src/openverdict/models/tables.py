"""SQLAlchemy ORM rows. The schema itself is created by the Alembic migrations."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _ts(**kwargs: Any) -> Any:
    return mapped_column(DateTime(timezone=True), **kwargs)


class ApiKeyRow(Base):
    __tablename__ = "api_keys"
    __table_args__ = (CheckConstraint("role IN ('client', 'analyst')", name="api_keys_role"),)

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(Text, unique=True)
    role: Mapped[str] = mapped_column(Text)
    key_hash: Mapped[str] = mapped_column(Text, unique=True)
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    revoked_at: Mapped[datetime | None] = _ts()


class OverrideRow(Base):
    __tablename__ = "overrides"
    __table_args__ = (
        CheckConstraint("target_type IN ('url', 'domain')", name="overrides_target_type"),
        CheckConstraint("verdict IN ('safe', 'malicious')", name="overrides_verdict"),
        Index(
            "overrides_active_target",
            "target_type",
            "target",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    target_type: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(Text)
    note: Mapped[str] = mapped_column(Text, server_default="")
    engine_verdict: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    created_by: Mapped[int] = mapped_column(ForeignKey("api_keys.id"))
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    deleted_at: Mapped[datetime | None] = _ts()


class AuditRow(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("audit_log_at", "at"),)

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    actor_key_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"))
    action: Mapped[str] = mapped_column(Text)
    override_id: Mapped[int] = mapped_column(ForeignKey("overrides.id"))
    before: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    at: Mapped[datetime] = _ts(server_default=func.now())


class JobRow(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("jobs_status_updated", "status", "updated_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    status: Mapped[str] = mapped_column(Text)
    total: Mapped[int] = mapped_column(Integer)
    done: Mapped[int] = mapped_column(Integer, server_default="0")
    attempts: Mapped[int] = mapped_column(Integer, server_default="0")
    created_by: Mapped[int] = mapped_column(ForeignKey("api_keys.id"))
    created_at: Mapped[datetime] = _ts(server_default=func.now())
    started_at: Mapped[datetime | None] = _ts()
    updated_at: Mapped[datetime] = _ts(server_default=func.now())
    finished_at: Mapped[datetime | None] = _ts()
    error: Mapped[str | None] = mapped_column(Text)


class JobItemRow(Base):
    __tablename__ = "job_items"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True
    )
    idx: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
