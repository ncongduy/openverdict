"""Verdict cache. Keys carry a version derived from feed versions and an overrides counter,
so a feed refresh or an override change invalidates old entries without deleting anything."""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from redis.asyncio import Redis

from openverdict.feeds.store import ALL_FEEDS
from openverdict.models.url import NormalizedUrl
from openverdict.models.verdict import DetectorFinding, Verdict

OVERRIDES_VERSION_KEY = "overrides:version"


@dataclass(frozen=True, slots=True)
class CachedVerdict:
    verdict: Verdict
    reasons: list[DetectorFinding]
    checked_at: datetime


def _dump(value: CachedVerdict) -> str:
    return json.dumps(
        {
            "verdict": value.verdict.value,
            "reasons": [[r.detector, r.verdict.value, r.detail] for r in value.reasons],
            "checked_at": value.checked_at.isoformat(),
        }
    )


def _load(raw: str | bytes) -> CachedVerdict:
    data = json.loads(raw)
    return CachedVerdict(
        verdict=Verdict(data["verdict"]),
        reasons=[DetectorFinding(d, Verdict(v), detail) for d, v, detail in data["reasons"]],
        checked_at=datetime.fromisoformat(data["checked_at"]),
    )


class VerdictCache:
    def __init__(self, valkey: Redis, ttl_seconds: int, feeds: Sequence[str] = ALL_FEEDS) -> None:
        self._valkey = valkey
        self._ttl = ttl_seconds
        self._feeds = list(feeds)

    async def version(self) -> str:
        keys = [f"feed:{feed}:active" for feed in self._feeds] + [OVERRIDES_VERSION_KEY]
        values = await self._valkey.mget(keys)
        joined = "|".join("-" if v is None else str(v) for v in values)
        return hashlib.sha256(joined.encode()).hexdigest()[:16]

    @staticmethod
    def _key(version: str, url: NormalizedUrl) -> str:
        return f"verdict:{version}:{url.sha256}"

    async def get_many(
        self, version: str, urls: Sequence[NormalizedUrl]
    ) -> list[CachedVerdict | None]:
        if not urls:
            return []
        raw = await self._valkey.mget([self._key(version, u) for u in urls])
        return [None if value is None else _load(value) for value in raw]

    async def set_many(
        self, version: str, items: Sequence[tuple[NormalizedUrl, CachedVerdict]]
    ) -> None:
        if not items:
            return
        async with self._valkey.pipeline(transaction=False) as pipe:
            for url, value in items:
                pipe.set(self._key(version, url), _dump(value), ex=self._ttl)
            await pipe.execute()

    async def bump_overrides(self) -> None:
        await self._valkey.incr(OVERRIDES_VERSION_KEY)
