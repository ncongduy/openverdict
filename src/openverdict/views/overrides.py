"""Override and audit-log schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from openverdict.models.overrides import AuditRecord, OverrideRecord


class OverrideCreateRequest(BaseModel):
    target_type: Literal["url", "domain"]
    target: str = Field(max_length=2048)
    verdict: Literal["safe", "malicious"]
    note: str = Field(default="", max_length=1000)


class OverrideView(BaseModel):
    id: int
    target_type: str
    target: str
    verdict: str
    note: str
    engine_verdict: str
    outcome: str
    created_by: str
    created_at: datetime

    @classmethod
    def of(cls, record: OverrideRecord) -> "OverrideView":
        return cls(
            id=record.id,
            target_type=record.target_type.value,
            target=record.target,
            verdict=record.verdict.value,
            note=record.note,
            engine_verdict=record.engine_verdict.value,
            outcome=record.outcome.value,
            created_by=record.created_by,
            created_at=record.created_at,
        )


class AuditEntryView(BaseModel):
    id: int
    actor: str
    action: str
    override_id: int
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    at: datetime

    @classmethod
    def of(cls, record: AuditRecord) -> "AuditEntryView":
        return cls(
            id=record.id,
            actor=record.actor,
            action=record.action,
            override_id=record.override_id,
            before=record.before,
            after=record.after,
            at=record.at,
        )
