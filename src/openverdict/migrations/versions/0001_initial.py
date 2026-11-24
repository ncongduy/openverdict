"""Initial schema: API keys, overrides, audit log, jobs.

Revision ID: 0001
Revises:
Create Date: 2026-11-24
"""

from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _ts(name: str, *, default_now: bool = False) -> sa.Column[datetime]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.func.now() if default_now else None,
        nullable=not default_now,
    )


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer, sa.Identity(), primary_key=True),
        sa.Column("name", sa.Text, nullable=False, unique=True),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("key_hash", sa.Text, nullable=False, unique=True),
        _ts("created_at", default_now=True),
        _ts("revoked_at"),
        sa.CheckConstraint("role IN ('client', 'analyst')", name="api_keys_role"),
    )
    op.create_table(
        "overrides",
        sa.Column("id", sa.Integer, sa.Identity(), primary_key=True),
        sa.Column("target_type", sa.Text, nullable=False),
        sa.Column("target", sa.Text, nullable=False),
        sa.Column("verdict", sa.Text, nullable=False),
        sa.Column("note", sa.Text, nullable=False, server_default=""),
        sa.Column("engine_verdict", sa.Text, nullable=False),
        sa.Column("outcome", sa.Text, nullable=False),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("api_keys.id"), nullable=False),
        _ts("created_at", default_now=True),
        _ts("deleted_at"),
        sa.CheckConstraint("target_type IN ('url', 'domain')", name="overrides_target_type"),
        sa.CheckConstraint("verdict IN ('safe', 'malicious')", name="overrides_verdict"),
    )
    op.create_index(
        "overrides_active_target",
        "overrides",
        ["target_type", "target"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, sa.Identity(), primary_key=True),
        sa.Column("actor_key_id", sa.Integer, sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("override_id", sa.Integer, sa.ForeignKey("overrides.id"), nullable=False),
        sa.Column("before", postgresql.JSONB),
        sa.Column("after", postgresql.JSONB),
        _ts("at", default_now=True),
    )
    op.create_index("audit_log_at", "audit_log", ["at"])
    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("total", sa.Integer, nullable=False),
        sa.Column("done", sa.Integer, nullable=False, server_default="0"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("api_keys.id"), nullable=False),
        _ts("created_at", default_now=True),
        _ts("started_at"),
        _ts("updated_at", default_now=True),
        _ts("finished_at"),
        sa.Column("error", sa.Text),
    )
    op.create_index("jobs_status_updated", "jobs", ["status", "updated_at"])
    op.create_table(
        "job_items",
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("idx", sa.Integer, primary_key=True),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("result", postgresql.JSONB),
    )


def downgrade() -> None:
    for table in ("job_items", "jobs", "audit_log", "overrides", "api_keys"):
        op.drop_table(table)
