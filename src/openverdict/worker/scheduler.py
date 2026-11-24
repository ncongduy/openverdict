"""The worker's periodic duties, run on every tick (about every 15 s)."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis

from openverdict.config import Settings
from openverdict.feeds.store import ALL_FEEDS, FeedStore
from openverdict.feeds.sync import FeedSyncer
from openverdict.metrics import FEED_LAST_SUCCESS
from openverdict.models.jobs import JobRepo
from openverdict.services.jobs import JobService
from openverdict.worker.maintenance import delete_old_jobs, sweep_stale_jobs, update_queue_depth

SWEEP_EVERY_SECONDS = 60
CLEANUP_EVERY_SECONDS = 3600


class Scheduler:
    def __init__(
        self,
        syncer: FeedSyncer,
        jobs: JobService,
        repo: JobRepo,
        valkey: Redis,
        feed_store: FeedStore,
        settings: Settings,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._syncer = syncer
        self._jobs = jobs
        self._repo = repo
        self._valkey = valkey
        self._feed_store = feed_store
        self._settings = settings
        self._clock = clock
        self.last_sweep: float | None = None
        self.last_cleanup: float | None = None

    async def tick(self) -> None:
        now = self._clock()
        await self._syncer.sync_due(now)
        if self.last_sweep is None or now - self.last_sweep >= SWEEP_EVERY_SECONDS:
            cutoff = datetime.now(UTC) - timedelta(seconds=self._settings.job_sweep_after_seconds)
            await sweep_stale_jobs(self._repo, self._jobs, cutoff)
            self.last_sweep = now
        if self.last_cleanup is None or now - self.last_cleanup >= CLEANUP_EVERY_SECONDS:
            cutoff = datetime.now(UTC) - timedelta(days=self._settings.job_retention_days)
            await delete_old_jobs(self._repo, cutoff)
            self.last_cleanup = now
        await update_queue_depth(self._valkey)
        for feed in ALL_FEEDS:
            synced_at = await self._feed_store.synced_at(feed)
            if synced_at is not None:
                FEED_LAST_SUCCESS.labels(feed=feed).set(synced_at)
