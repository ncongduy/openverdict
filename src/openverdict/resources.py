"""Wiring shared by the api and worker processes."""

import logging
from dataclasses import dataclass

import httpx
from redis.asyncio import Redis, from_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from openverdict.config import Settings
from openverdict.detectors.url.allowlist import AllowlistDetector
from openverdict.detectors.url.base import UrlDetector
from openverdict.detectors.url.feeds import FeedDetector
from openverdict.detectors.url.heuristics import HeuristicsDetector
from openverdict.detectors.url.safe_browsing import SafeBrowsingDetector
from openverdict.feeds.store import PHISHING_DB, URLHAUS, FeedStore
from openverdict.models.api_keys import ApiKeyRepo
from openverdict.models.db import create_engine, create_sessionmaker
from openverdict.models.overrides import OverrideRepo
from openverdict.services.cache import VerdictCache
from openverdict.services.pipeline import UrlPipeline

log = logging.getLogger(__name__)


@dataclass
class Resources:
    settings: Settings
    engine: AsyncEngine
    db: async_sessionmaker[AsyncSession]
    valkey: Redis
    http: httpx.AsyncClient
    feed_store: FeedStore
    cache: VerdictCache
    keys: ApiKeyRepo
    overrides: OverrideRepo
    pipeline: UrlPipeline

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.valkey.aclose()
        await self.engine.dispose()


def build_detectors(
    settings: Settings, store: FeedStore, http: httpx.AsyncClient
) -> list[UrlDetector]:
    detectors: list[UrlDetector] = [
        FeedDetector(URLHAUS, store),
        FeedDetector(PHISHING_DB, store),
        AllowlistDetector(store),
        HeuristicsDetector(),
    ]
    if settings.safe_browsing_enabled:
        if settings.safe_browsing_api_key is None:
            log.warning("safe_browsing enabled but OPENVERDICT_SAFE_BROWSING_API_KEY is not set")
        else:
            key = settings.safe_browsing_api_key.get_secret_value()
            detectors.append(SafeBrowsingDetector(http, key))
    return detectors


async def build_resources(settings: Settings) -> Resources:
    engine = create_engine(settings.database_url)
    db = create_sessionmaker(engine)
    valkey = from_url(settings.valkey_url, decode_responses=True, socket_connect_timeout=2)
    http = httpx.AsyncClient(timeout=httpx.Timeout(60.0))
    feed_store = FeedStore(valkey)
    cache = VerdictCache(valkey, settings.cache_ttl_seconds)
    overrides = OverrideRepo(db)
    pipeline = UrlPipeline(
        build_detectors(settings, feed_store, http),
        cache,
        overrides,
        settings.detector_timeout_seconds,
    )
    return Resources(
        settings=settings,
        engine=engine,
        db=db,
        valkey=valkey,
        http=http,
        feed_store=feed_store,
        cache=cache,
        keys=ApiKeyRepo(db),
        overrides=overrides,
        pipeline=pipeline,
    )
