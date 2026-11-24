"""Async URL-check jobs. Postgres is the source of truth; Valkey only dispatches job IDs."""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import Table, bindparam, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from openverdict.models.tables import JobItemRow, JobRow

_ITEMS = cast(Table, JobItemRow.__table__)


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class JobRecord:
    id: uuid.UUID
    status: JobStatus
    total: int
    done: int
    attempts: int
    created_by: int
    created_at: datetime
    finished_at: datetime | None
    error: str | None


def _record(row: JobRow) -> JobRecord:
    return JobRecord(
        id=row.id,
        status=JobStatus(row.status),
        total=row.total,
        done=row.done,
        attempts=row.attempts,
        created_by=row.created_by,
        created_at=row.created_at,
        finished_at=row.finished_at,
        error=row.error,
    )


class JobRepo:
    def __init__(self, db: async_sessionmaker[AsyncSession]) -> None:
        self._db = db

    async def create(self, owner_key_id: int, urls: Sequence[str]) -> JobRecord:
        job_id = uuid.uuid4()
        async with self._db() as session, session.begin():
            row = JobRow(
                id=job_id, status=JobStatus.QUEUED.value, total=len(urls), created_by=owner_key_id
            )
            session.add(row)
            await session.flush()
            await session.execute(
                insert(_ITEMS),
                [{"job_id": job_id, "idx": i, "url": url} for i, url in enumerate(urls)],
            )
            await session.refresh(row)
        return _record(row)

    async def get(self, job_id: uuid.UUID) -> JobRecord | None:
        async with self._db() as session:
            row = await session.get(JobRow, job_id)
        return None if row is None else _record(row)

    async def results(self, job_id: uuid.UUID, offset: int, limit: int) -> list[dict[str, Any]]:
        query = (
            select(JobItemRow.result)
            .where(JobItemRow.job_id == job_id, JobItemRow.result.is_not(None))
            .order_by(JobItemRow.idx)
            .offset(offset)
            .limit(limit)
        )
        async with self._db() as session:
            return [r for r in (await session.execute(query)).scalars() if r is not None]

    async def start(self, job_id: uuid.UUID) -> JobRecord | None:
        statement = (
            update(JobRow)
            .where(JobRow.id == job_id)
            .values(
                status=JobStatus.RUNNING.value,
                attempts=JobRow.attempts + 1,
                started_at=func.coalesce(JobRow.started_at, func.now()),
                updated_at=func.now(),
            )
            .returning(JobRow)
        )
        async with self._db() as session, session.begin():
            row = (await session.execute(statement)).scalar_one_or_none()
        return None if row is None else _record(row)

    async def pending_items(self, job_id: uuid.UUID, limit: int) -> list[tuple[int, str]]:
        query = (
            select(JobItemRow.idx, JobItemRow.url)
            .where(JobItemRow.job_id == job_id, JobItemRow.result.is_(None))
            .order_by(JobItemRow.idx)
            .limit(limit)
        )
        async with self._db() as session:
            return [(idx, url) for idx, url in (await session.execute(query)).all()]

    async def save_results(
        self, job_id: uuid.UUID, results: Sequence[tuple[int, dict[str, Any]]]
    ) -> int:
        """Store results for items that have none yet (idempotent); returns the new done count."""
        statement = (
            update(_ITEMS)
            .where(
                _ITEMS.c.job_id == bindparam("b_job"),
                _ITEMS.c.idx == bindparam("b_idx"),
                _ITEMS.c.result.is_(None),
            )
            .values(result=bindparam("b_result"))
        )
        done_count = (
            select(func.count())
            .select_from(_ITEMS)
            .where(_ITEMS.c.job_id == job_id, _ITEMS.c.result.is_not(None))
            .scalar_subquery()
        )
        async with self._db() as session, session.begin():
            if results:
                params = [{"b_job": job_id, "b_idx": i, "b_result": r} for i, r in results]
                await session.execute(statement, params)
            done = (
                await session.execute(
                    update(JobRow)
                    .where(JobRow.id == job_id)
                    .values(done=done_count, updated_at=func.now())
                    .returning(JobRow.done)
                )
            ).scalar_one()
        return done

    async def finish(self, job_id: uuid.UUID, status: JobStatus, error: str | None = None) -> None:
        statement = (
            update(JobRow)
            .where(JobRow.id == job_id)
            .values(status=status.value, error=error, finished_at=func.now(), updated_at=func.now())
        )
        async with self._db() as session, session.begin():
            await session.execute(statement)

    async def stale(self, older_than: datetime) -> list[uuid.UUID]:
        query = select(JobRow.id).where(
            JobRow.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
            JobRow.updated_at < older_than,
        )
        async with self._db() as session:
            return list((await session.execute(query)).scalars())

    async def delete_older_than(self, cutoff: datetime) -> int:
        """Retention: remove jobs (and, by cascade, their items) created before the cutoff."""
        async with self._db() as session, session.begin():
            removed = await session.execute(
                delete(JobRow).where(JobRow.created_at < cutoff).returning(JobRow.id)
            )
            return len(removed.all())
