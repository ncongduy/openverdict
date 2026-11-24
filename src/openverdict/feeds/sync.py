"""Download, parse and publish feeds on a schedule. A failed sync never wipes existing data."""

import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

import httpx
from redis.asyncio import Redis

from openverdict.config import Settings
from openverdict.feeds.parsers import (
    ParsedFeed,
    parse_domain_lines,
    parse_tranco,
    parse_url_lines,
    parse_urlhaus_csv,
)
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS, FeedStore
from openverdict.metrics import FEED_ENTRIES, FEED_LAST_SUCCESS, FEED_SYNC_FAILURES

log = logging.getLogger(__name__)

# httpx logs every request URL at INFO; the URLhaus export URL carries the Auth-Key in its path.
for _noisy in ("httpx", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

LOCK_TTL_SECONDS = 600
RETRY_SECONDS = 300

Fetch = Callable[[httpx.AsyncClient], Awaitable[ParsedFeed]]


@dataclass(frozen=True, slots=True)
class FeedSource:
    name: str
    interval_seconds: int
    fetch: Fetch


class EmptyFeedError(Exception):
    """The download parsed to nothing: treat as a failure, keep the old version."""


async def _download(http: httpx.AsyncClient, url: str) -> httpx.Response:
    response = await http.get(url, follow_redirects=True)
    response.raise_for_status()
    return response


def build_sources(settings: Settings) -> list[FeedSource]:
    sources: list[FeedSource] = []

    urlhaus_url = settings.urlhaus_download_url()
    if urlhaus_url is None:
        log.warning("urlhaus sync disabled: OPENVERDICT_URLHAUS_AUTH_KEY is not set")
    else:

        async def fetch_urlhaus(http: httpx.AsyncClient) -> ParsedFeed:
            return parse_urlhaus_csv((await _download(http, urlhaus_url)).text)

        sources.append(FeedSource(URLHAUS, settings.urlhaus_interval_seconds, fetch_urlhaus))

    async def fetch_phishing_db(http: httpx.AsyncClient) -> ParsedFeed:
        feed = parse_url_lines((await _download(http, settings.phishing_db_links_url)).text)
        domains = (await _download(http, settings.phishing_db_domains_url)).text
        feed.hosts |= parse_domain_lines(domains)
        return feed

    async def fetch_allowlist(http: httpx.AsyncClient) -> ParsedFeed:
        content = (await _download(http, settings.tranco_url)).content
        return ParsedFeed(hosts=set(parse_tranco(content, settings.allowlist_size)))

    sources.append(
        FeedSource(PHISHING_DB, settings.phishing_db_interval_seconds, fetch_phishing_db)
    )
    sources.append(FeedSource(ALLOWLIST, settings.tranco_interval_seconds, fetch_allowlist))
    return sources


class FeedSyncer:
    def __init__(
        self,
        store: FeedStore,
        valkey: Redis,
        http: httpx.AsyncClient,
        sources: Sequence[FeedSource],
    ) -> None:
        self._store = store
        self._valkey = valkey
        self._http = http
        self.sources = list(sources)

    async def sync(self, source: FeedSource) -> bool:
        lock_key = f"lock:feed:{source.name}"
        token = uuid.uuid4().hex
        if not await self._valkey.set(lock_key, token, nx=True, ex=LOCK_TTL_SECONDS):
            return False
        try:
            return await self._sync_locked(source)
        finally:
            if await self._valkey.get(lock_key) == token:
                await self._valkey.delete(lock_key)

    async def _sync_locked(self, source: FeedSource) -> bool:
        try:
            feed = await source.fetch(self._http)
            if not feed.urls and not feed.hosts:
                raise EmptyFeedError
        except Exception as exc:  # noqa: BLE001 - any failure keeps the old version
            status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
            # Never log the URL or str(exc): the URLhaus URL contains the Auth-Key.
            log.warning(
                "feed sync failed",
                extra={"feed": source.name, "error": type(exc).__name__, "status": status},
            )
            FEED_SYNC_FAILURES.labels(feed=source.name).inc()
            return False

        await self._store.publish(source.name, feed.urls, feed.hosts)
        now = time.time()
        await self._store.mark_synced(source.name, now)
        FEED_LAST_SUCCESS.labels(feed=source.name).set(now)
        FEED_ENTRIES.labels(feed=source.name, kind="urls").set(len(feed.urls))
        FEED_ENTRIES.labels(feed=source.name, kind="hosts").set(len(feed.hosts))
        log.info(
            "feed synced",
            extra={"feed": source.name, "urls": len(feed.urls), "skipped": feed.skipped},
        )
        return True

    async def sync_due(self, now: float) -> None:
        for source in self.sources:
            last = await self._store.synced_at(source.name)
            if last is not None and now - last < source.interval_seconds:
                continue
            # After a failure, wait before retrying: never hammer a feed every tick.
            attempted = await self._store.attempted_at(source.name)
            retry_after = min(source.interval_seconds, RETRY_SECONDS)
            if attempted is not None and now - attempted < retry_after:
                continue
            await self._store.mark_attempted(source.name, now)
            await self.sync(source)
