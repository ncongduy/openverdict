"""Analyst overrides and their audit trail."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from openverdict.models.api_keys import Principal
from openverdict.models.tables import ApiKeyRow, AuditRow, OverrideRow
from openverdict.models.url import NormalizedUrl, host_suffixes
from openverdict.models.verdict import OverrideOutcome, Verdict


class TargetType(StrEnum):
    URL = "url"
    DOMAIN = "domain"


@dataclass(frozen=True, slots=True)
class OverrideMatch:
    id: int
    verdict: Verdict
    note: str


@dataclass(frozen=True, slots=True)
class OverrideRecord:
    id: int
    target_type: TargetType
    target: str
    verdict: Verdict
    note: str
    engine_verdict: Verdict
    outcome: OverrideOutcome
    created_by: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuditRecord:
    id: int
    actor: str
    action: str
    override_id: int
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    at: datetime


def _snapshot(row: OverrideRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "target_type": row.target_type,
        "target": row.target,
        "verdict": row.verdict,
        "note": row.note,
    }


def _record(row: OverrideRow, created_by: str) -> OverrideRecord:
    return OverrideRecord(
        id=row.id,
        target_type=TargetType(row.target_type),
        target=row.target,
        verdict=Verdict(row.verdict),
        note=row.note,
        engine_verdict=Verdict(row.engine_verdict),
        outcome=OverrideOutcome(row.outcome),
        created_by=created_by,
        created_at=row.created_at,
    )


class OverrideRepo:
    def __init__(self, db: async_sessionmaker[AsyncSession]) -> None:
        self._db = db

    async def create(
        self,
        actor: Principal,
        target_type: TargetType,
        target: str,
        verdict: Verdict,
        note: str,
        engine_verdict: Verdict,
        outcome: OverrideOutcome,
    ) -> OverrideRecord:
        """Insert an override; an active one on the same target is replaced in the same tx."""
        async with self._db() as session, session.begin():
            previous = (
                await session.execute(
                    select(OverrideRow)
                    .where(
                        OverrideRow.target_type == target_type.value,
                        OverrideRow.target == target,
                        OverrideRow.deleted_at.is_(None),
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            before = None
            if previous is not None:
                before = _snapshot(previous)
                previous.deleted_at = func.now()
                await session.flush()
            row = OverrideRow(
                target_type=target_type.value,
                target=target,
                verdict=verdict.value,
                note=note,
                engine_verdict=engine_verdict.value,
                outcome=outcome.value,
                created_by=actor.key_id,
            )
            session.add(row)
            await session.flush()
            await session.refresh(row)
            session.add(
                AuditRow(
                    actor_key_id=actor.key_id,
                    action="override.create",
                    override_id=row.id,
                    before=before,
                    after=_snapshot(row),
                )
            )
        return _record(row, actor.name)

    async def deactivate(self, actor: Principal, override_id: int) -> bool:
        async with self._db() as session, session.begin():
            row = (
                await session.execute(
                    select(OverrideRow)
                    .where(OverrideRow.id == override_id, OverrideRow.deleted_at.is_(None))
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            row.deleted_at = func.now()
            session.add(
                AuditRow(
                    actor_key_id=actor.key_id,
                    action="override.delete",
                    override_id=row.id,
                    before=_snapshot(row),
                    after=None,
                )
            )
        return True

    async def list_active(self) -> list[OverrideRecord]:
        query = (
            select(OverrideRow, ApiKeyRow.name)
            .join(ApiKeyRow, ApiKeyRow.id == OverrideRow.created_by)
            .where(OverrideRow.deleted_at.is_(None))
            .order_by(OverrideRow.id.desc())
        )
        async with self._db() as session:
            rows = (await session.execute(query)).all()
        return [_record(row, name) for row, name in rows]

    async def audit_log(self, limit: int, offset: int) -> list[AuditRecord]:
        query = (
            select(AuditRow, ApiKeyRow.name)
            .join(ApiKeyRow, ApiKeyRow.id == AuditRow.actor_key_id)
            .order_by(AuditRow.id.desc())
            .limit(limit)
            .offset(offset)
        )
        async with self._db() as session:
            rows = (await session.execute(query)).all()
        return [
            AuditRecord(
                id=row.id,
                actor=name,
                action=row.action,
                override_id=row.override_id,
                before=row.before,
                after=row.after,
                at=row.at,
            )
            for row, name in rows
        ]

    async def match(self, urls: Sequence[NormalizedUrl]) -> dict[str, OverrideMatch]:
        """Active override per URL: exact URL beats domain; the longest matching domain wins."""
        if not urls:
            return {}
        suffixes = {s for u in urls for s in host_suffixes(u.host)}
        query = select(OverrideRow).where(
            OverrideRow.deleted_at.is_(None),
            or_(
                and_(
                    OverrideRow.target_type == TargetType.URL.value,
                    OverrideRow.target.in_([u.url for u in urls]),
                ),
                and_(
                    OverrideRow.target_type == TargetType.DOMAIN.value,
                    OverrideRow.target.in_(suffixes),
                ),
            ),
        )
        async with self._db() as session:
            rows = (await session.execute(query)).scalars().all()
        exact = {r.target: r for r in rows if r.target_type == TargetType.URL.value}
        domains = {r.target: r for r in rows if r.target_type == TargetType.DOMAIN.value}
        matches: dict[str, OverrideMatch] = {}
        for url in urls:
            row = exact.get(url.url)
            if row is None:
                # host_suffixes is most-specific first, so the first hit is the longest domain.
                row = next((domains[s] for s in host_suffixes(url.host) if s in domains), None)
            if row is not None:
                matches[url.url] = OverrideMatch(row.id, Verdict(row.verdict), row.note)
        return matches
