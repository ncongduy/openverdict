"""Job consumer on a Valkey stream: at-least-once delivery, idempotent processing."""

import logging
import time
import uuid
from typing import cast

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from openverdict.metrics import JOB_DURATION, JOBS_TOTAL
from openverdict.models.jobs import JobRepo, JobStatus
from openverdict.services.jobs import JOB_GROUP, JOB_STREAM
from openverdict.services.pipeline import UrlPipeline
from openverdict.views.url_checks import result_to_view

log = logging.getLogger(__name__)

Message = tuple[str, dict[str, str] | None]


class JobConsumer:
    def __init__(
        self,
        valkey: Redis,
        repo: JobRepo,
        pipeline: UrlPipeline,
        name: str,
        reclaim_idle_ms: int,
        chunk_size: int = 100,
        max_attempts: int = 3,
    ) -> None:
        self._valkey = valkey
        self._repo = repo
        self._pipeline = pipeline
        self.name = name
        self._reclaim_idle_ms = reclaim_idle_ms
        self._chunk_size = chunk_size
        self._max_attempts = max_attempts

    async def ensure_group(self) -> None:
        # Start at 0, not $: jobs enqueued before the group existed (first start, or after
        # Valkey lost the stream and the sweeper re-enqueued) must still be consumed.
        try:
            await self._valkey.xgroup_create(JOB_STREAM, JOB_GROUP, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def run_once(self, block_ms: int = 5000) -> int:
        """Reclaim messages from dead consumers first, else read one new message."""
        try:
            messages = await self._next_messages(block_ms)
        except ResponseError as exc:
            if "NOGROUP" not in str(exc):
                raise
            log.warning("job consumer group missing; recreating it")
            await self.ensure_group()
            return 0
        for message_id, fields in messages:
            if await self._handle(fields):
                await self._valkey.xack(JOB_STREAM, JOB_GROUP, message_id)
        return len(messages)

    async def _next_messages(self, block_ms: int) -> list[Message]:
        reclaimed = await self._valkey.xautoclaim(
            JOB_STREAM, JOB_GROUP, self.name, self._reclaim_idle_ms, start_id="0-0", count=10
        )
        messages: list[Message] = list(reclaimed[1])
        if messages:
            return messages
        # redis-py types this loosely; the reply is [(stream, [(id, fields), ...])].
        response = cast(
            list[tuple[str, list[Message]]] | None,
            await self._valkey.xreadgroup(
                JOB_GROUP, self.name, {JOB_STREAM: ">"}, count=1, block=block_ms
            ),
        )
        return [entry for _, entries in response or [] for entry in entries]

    async def _handle(self, fields: dict[str, str] | None) -> bool:
        """Process one message; True means acknowledge it."""
        try:
            job_id = uuid.UUID((fields or {})["job_id"])
        except KeyError, ValueError:
            log.warning("dropping malformed job message")
            return True
        try:
            await self.process(job_id)
        except Exception as exc:  # noqa: BLE001 - left unacked, reclaimed after the idle time
            log.warning(
                "job processing failed; will be reclaimed",
                extra={"job_id": str(job_id), "error": type(exc).__name__},
            )
            return False
        return True

    async def process(self, job_id: uuid.UUID) -> None:
        job = await self._repo.get(job_id)
        if job is None or job.status in (JobStatus.DONE, JobStatus.FAILED):
            return
        if job.attempts >= self._max_attempts:
            await self._repo.finish(job_id, JobStatus.FAILED, "max attempts exceeded")
            JOBS_TOTAL.labels(status=JobStatus.FAILED.value).inc()
            return
        started = time.perf_counter()
        await self._repo.start(job_id)
        while items := await self._repo.pending_items(job_id, self._chunk_size):
            results = await self._pipeline.check([url for _, url in items])
            await self._repo.save_results(
                job_id,
                [
                    (idx, result_to_view(result).model_dump(mode="json"))
                    for (idx, _), result in zip(items, results, strict=True)
                ],
            )
        await self._repo.finish(job_id, JobStatus.DONE)
        JOB_DURATION.observe(time.perf_counter() - started)
        JOBS_TOTAL.labels(status=JobStatus.DONE.value).inc()
