"""Periodic job maintenance: recover lost jobs, enforce retention, report queue depth."""

from datetime import datetime

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from openverdict.metrics import JOB_QUEUE_DEPTH
from openverdict.models.jobs import JobRepo
from openverdict.services.jobs import JOB_GROUP, JOB_STREAM, JobService


async def sweep_stale_jobs(repo: JobRepo, jobs: JobService, older_than: datetime) -> int:
    """Re-enqueue queued/running jobs with no progress since `older_than` (lost or failed XADD)."""
    stale = await repo.stale(older_than)
    for job_id in stale:
        await jobs.enqueue(job_id)
    await repo.touch(stale)
    return len(stale)


async def delete_old_jobs(repo: JobRepo, cutoff: datetime) -> int:
    return await repo.delete_older_than(cutoff)


async def update_queue_depth(valkey: Redis) -> int:
    try:
        groups = await valkey.xinfo_groups(JOB_STREAM)
    except ResponseError:  # stream does not exist yet
        groups = []
    depth = sum(
        int(group.get("lag") or 0) + int(group.get("pending") or 0)
        for group in groups
        if group.get("name") == JOB_GROUP
    )
    JOB_QUEUE_DEPTH.set(depth)
    return depth
