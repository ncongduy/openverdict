"""Versioned feed sets in Valkey: publish a full new version, then switch the active pointer."""

import hashlib
import itertools
import uuid
from collections.abc import Iterable, Mapping, Sequence

from redis.asyncio import Redis

URLHAUS = "urlhaus"
PHISHING_DB = "phishing_db"
ALLOWLIST = "allowlist"
ALL_FEEDS = (URLHAUS, PHISHING_DB, ALLOWLIST)

_CHUNK = 5000


def url_member(url: str) -> str:
    """Feed hash field for a normalized URL: 32 hex chars of its SHA-256 (keeps Valkey small)."""
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def _text(value: bytes | str | None) -> str | None:
    if isinstance(value, bytes):
        return value.decode()
    return value


def _active_key(feed: str) -> str:
    return f"feed:{feed}:active"


def _version_keys(feed: str, version: str) -> tuple[str, str]:
    return f"feed:{feed}:{version}:urls", f"feed:{feed}:{version}:hosts"


class FeedStore:
    def __init__(self, valkey: Redis) -> None:
        self._valkey = valkey

    async def publish(self, feed: str, urls: Mapping[str, str], hosts: Iterable[str]) -> str:
        version = uuid.uuid4().hex[:12]
        urls_key, hosts_key = _version_keys(feed, version)
        members = ((url_member(url), meta) for url, meta in urls.items())
        for chunk in itertools.batched(members, _CHUNK, strict=False):
            await self._valkey.hset(urls_key, mapping=dict(chunk))
        for host_chunk in itertools.batched(hosts, _CHUNK, strict=False):
            await self._valkey.sadd(hosts_key, *host_chunk)
        previous = await self._valkey.set(_active_key(feed), version, get=True)
        if isinstance(previous, bytes):
            previous = previous.decode()
        if isinstance(previous, str):
            await self._valkey.unlink(*_version_keys(feed, previous))
        return version

    async def active_versions(self, feeds: Sequence[str]) -> dict[str, str | None]:
        values = await self._valkey.mget([_active_key(f) for f in feeds])
        return {feed: _text(value) for feed, value in zip(feeds, values, strict=True)}

    async def _active(self, feed: str) -> str | None:
        return _text(await self._valkey.get(_active_key(feed)))

    async def match_urls(self, feed: str, urls: Sequence[str]) -> list[str | None]:
        version = await self._active(feed)
        if version is None or not urls:
            return [None] * len(urls)
        urls_key, _ = _version_keys(feed, version)
        found = await self._valkey.hmget(urls_key, [url_member(u) for u in urls])
        return [_text(value) for value in found]

    async def match_hosts(self, feed: str, hosts: Sequence[str]) -> list[bool]:
        version = await self._active(feed)
        if version is None or not hosts:
            return [False] * len(hosts)
        _, hosts_key = _version_keys(feed, version)
        flags = await self._valkey.smismember(hosts_key, list(hosts))
        return [bool(flag) for flag in flags]

    async def mark_synced(self, feed: str, at: float) -> None:
        await self._valkey.set(f"feed:{feed}:synced_at", repr(at))

    async def synced_at(self, feed: str) -> float | None:
        value = await self._valkey.get(f"feed:{feed}:synced_at")
        return None if value is None else float(value)
