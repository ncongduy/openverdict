"""Top-sites allowlist: the only detector (besides analyst overrides) that can say `safe`."""

from collections.abc import Sequence

from openverdict.detectors.url.user_content import is_user_content
from openverdict.feeds.store import ALLOWLIST, FeedStore
from openverdict.models.url import NormalizedUrl, host_suffixes
from openverdict.models.verdict import DetectorFinding, Verdict


async def first_suffix_in(store: FeedStore, feed: str, hosts: Sequence[str]) -> list[str | None]:
    """Per host, the most specific suffix present in the feed's host set (one Valkey call)."""
    suffixes = [host_suffixes(host) for host in hosts]
    flat = [s for group in suffixes for s in group]
    flags = iter(await store.match_hosts(feed, flat))
    matches: list[str | None] = []
    for group in suffixes:
        hits = [suffix for suffix in group if next(flags)]
        matches.append(hits[0] if hits else None)
    return matches


async def allowlisted(store: FeedStore, hosts: Sequence[str]) -> list[str | None]:
    """Allowlisted suffix per host; user-content hosts are never allowlisted."""
    matches = await first_suffix_in(store, ALLOWLIST, hosts)
    return [None if is_user_content(h) else m for h, m in zip(hosts, matches, strict=True)]


class AllowlistDetector:
    name = "allowlist"

    def __init__(self, store: FeedStore) -> None:
        self._store = store

    async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]:
        matches = await allowlisted(self._store, [u.host for u in urls])
        return [
            None if m is None else DetectorFinding(self.name, Verdict.SAFE, f"top-sites list: {m}")
            for m in matches
        ]
