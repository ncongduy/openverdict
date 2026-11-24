import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.jobs import JobRepo, JobStatus
from openverdict.models.tables import JobRow
from openverdict.services.jobs import JOB_GROUP, JOB_STREAM, JobService
from openverdict.worker.consumer import JobConsumer
from openverdict.worker.maintenance import delete_old_jobs, sweep_stale_jobs, update_queue_depth
from openverdict.worker.scheduler import Scheduler
from tests.helpers import sample

URLS = [f"http://bulk-{i}.test/" for i in range(250)]
URLS[7] = "http://malware-drop.test/payload.exe"


@pytest.fixture
async def env(resources, db, valkey, published_feeds):
    owner, _ = await ApiKeyRepo(db).create("owner", Role.CLIENT)
    repo = JobRepo(db)
    jobs = JobService(repo, valkey)

    def consumer(name="c1", idle=300_000):
        return JobConsumer(valkey, repo, resources.pipeline, name, idle)

    await consumer().ensure_group()
    return owner, repo, jobs, consumer


async def test_process_job(env, valkey):
    owner, repo, jobs, consumer = env
    before = sample("openverdict_jobs_total", status="done")
    job = await jobs.submit(owner, URLS)
    assert await consumer().run_once(block_ms=100) == 1
    done = await repo.get(job.id)
    assert (done.status, done.done, done.total) == (JobStatus.DONE, 250, 250)
    page = await repo.results(job.id, offset=0, limit=1000)
    assert len(page) == 250
    assert page[7]["verdict"] == "malicious" and page[8]["verdict"] == "unknown"
    assert [r["url"] for r in await repo.results(job.id, offset=100, limit=50)] == URLS[100:150]
    assert (await valkey.xpending(JOB_STREAM, JOB_GROUP))["pending"] == 0
    assert sample("openverdict_jobs_total", status="done") == before + 1


async def test_reclaim_after_crash(env, valkey):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS[:10])
    await valkey.xreadgroup(JOB_GROUP, "dead", {JOB_STREAM: ">"}, count=1)  # never acked
    assert await consumer("c2", idle=0).run_once(block_ms=100) == 1
    assert (await repo.get(job.id)).status is JobStatus.DONE


async def test_resume_and_concurrent_duplicates(env):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS)
    await repo.save_results(job.id, [(i, {"url": URLS[i], "marker": True}) for i in range(100)])
    await jobs.enqueue(job.id)  # a second message for the same job
    await asyncio.gather(consumer("a").run_once(100), consumer("b").run_once(100))
    assert (await repo.get(job.id)).done == 250
    first = await repo.results(job.id, offset=0, limit=100)
    assert all(r.get("marker") for r in first)


async def test_max_attempts(env, db):
    owner, repo, jobs, consumer = env
    job = await jobs.submit(owner, URLS[:1])
    async with db() as s, s.begin():
        await s.execute(update(JobRow).where(JobRow.id == job.id).values(attempts=3))
    before = sample("openverdict_jobs_total", status="failed")
    await consumer().run_once(100)
    assert (await repo.get(job.id)).status is JobStatus.FAILED
    assert sample("openverdict_jobs_total", status="failed") == before + 1


async def test_sweeper_cleanup_and_gauge(env, db, valkey):
    owner, repo, jobs, _ = env
    stale = await repo.create(owner.key_id, URLS[:1])  # created without XADD
    fresh = await repo.create(owner.key_id, URLS[:1])
    old = await repo.create(owner.key_id, URLS[:1])
    now = datetime.now(UTC)
    async with db() as s, s.begin():
        await s.execute(
            update(JobRow)
            .where(JobRow.id == stale.id)
            .values(updated_at=now - timedelta(minutes=10))
        )
        await s.execute(
            update(JobRow).where(JobRow.id == old.id).values(created_at=now - timedelta(days=8))
        )
    assert await sweep_stale_jobs(repo, jobs, now - timedelta(minutes=5)) == 1
    # A swept job counts as touched, so the next sweep does not enqueue it again.
    assert await sweep_stale_jobs(repo, jobs, now - timedelta(minutes=5)) == 0
    ids = [f["job_id"] for _, f in await valkey.xrange(JOB_STREAM)]
    assert str(stale.id) in ids and str(fresh.id) not in ids
    assert await update_queue_depth(valkey) == len(ids)
    assert await delete_old_jobs(repo, now - timedelta(days=7)) == 1
    assert await repo.get(old.id) is None and await repo.get(fresh.id) is not None


class FakeSyncer:
    def __init__(self):
        self.calls = []

    async def sync_due(self, now):
        self.calls.append(now)


async def test_scheduler_cadence(env, valkey, feed_store, settings):
    _, repo, jobs, _ = env
    clock = iter([1000.0, 1015.0, 1075.0])
    syncer = FakeSyncer()
    sched = Scheduler(syncer, jobs, repo, valkey, feed_store, settings, clock=lambda: next(clock))
    for _ in range(3):
        await sched.tick()
    assert syncer.calls == [1000.0, 1015.0, 1075.0]
    # Sweeps every 60 s (ran at 1000 and 1075, skipped 1015); cleanup hourly (only 1000).
    assert sched.last_sweep == 1075.0 and sched.last_cleanup == 1000.0
