"""Job submission and dispatch over a Valkey stream."""

import logging
import uuid
from collections.abc import Sequence

from redis.asyncio import Redis
from redis.exceptions import RedisError

from openverdict.models.api_keys import Principal, Role
from openverdict.models.jobs import JobRecord, JobRepo

log = logging.getLogger(__name__)

JOB_STREAM = "openverdict:jobs"
JOB_GROUP = "workers"


class JobService:
    def __init__(self, repo: JobRepo, valkey: Redis) -> None:
        self._repo = repo
        self._valkey = valkey

    async def submit(self, owner: Principal, urls: Sequence[str]) -> JobRecord:
        job = await self._repo.create(owner.key_id, urls)
        try:
            await self.enqueue(job.id)
        except RedisError, OSError:
            # The job is safely in Postgres; the worker's sweeper enqueues it later.
            log.warning("job enqueue failed; sweeper will retry", extra={"job_id": str(job.id)})
        return job

    async def enqueue(self, job_id: uuid.UUID) -> None:
        await self._valkey.xadd(JOB_STREAM, {"job_id": str(job_id)})

    async def visible_job(self, job_id: uuid.UUID, requester: Principal) -> JobRecord | None:
        job = await self._repo.get(job_id)
        if job is None:
            return None
        if requester.role is not Role.ANALYST and job.created_by != requester.key_id:
            return None
        return job
