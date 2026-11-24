"""Worker process: consume jobs and run the scheduler until SIGTERM/SIGINT."""

import asyncio
import contextlib
import logging
import os
import signal
import socket

from prometheus_client import start_http_server

from openverdict.config import Settings
from openverdict.feeds.sync import FeedSyncer, build_sources
from openverdict.logs import configure_logging
from openverdict.resources import build_resources
from openverdict.worker.consumer import JobConsumer
from openverdict.worker.scheduler import Scheduler

log = logging.getLogger(__name__)

TICK_SECONDS = 15


async def run_worker(settings: Settings) -> None:
    configure_logging(settings.log_level)
    resources = await build_resources(settings)
    start_http_server(settings.worker_metrics_port)
    consumer = JobConsumer(
        resources.valkey,
        resources.job_repo,
        resources.pipeline,
        f"{socket.gethostname()}-{os.getpid()}",
        settings.job_reclaim_idle_seconds * 1000,
    )
    syncer = FeedSyncer(
        resources.feed_store, resources.valkey, resources.http, build_sources(settings)
    )
    scheduler = Scheduler(
        syncer,
        resources.jobs,
        resources.job_repo,
        resources.valkey,
        resources.feed_store,
        settings,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    async def consume() -> None:
        while not stop.is_set():
            try:
                await consumer.run_once(block_ms=2000)
            except Exception as exc:  # noqa: BLE001 - keep consuming after transient errors
                log.warning("consumer error", extra={"error": type(exc).__name__})
                await asyncio.sleep(1)

    async def schedule() -> None:
        while not stop.is_set():
            try:
                await scheduler.tick()
            except Exception as exc:  # noqa: BLE001 - keep scheduling after transient errors
                log.warning("scheduler error", extra={"error": type(exc).__name__})
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), TICK_SECONDS)

    try:
        await consumer.ensure_group()
        log.info("worker started", extra={"consumer": consumer.name})
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(consume())
            tasks.create_task(schedule())
    finally:
        await resources.aclose()
        log.info("worker stopped")
