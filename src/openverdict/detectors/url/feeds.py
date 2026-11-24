"""Threat-feed detector: exact URL match is malicious, host-only match is suspicious."""

from collections.abc import Sequence

from openverdict.detectors.url.allowlist import allowlisted, first_suffix_in
from openverdict.detectors.url.user_content import is_user_content
from openverdict.feeds.store import FeedStore
from openverdict.models.url import NormalizedUrl
from openverdict.models.verdict import DetectorFinding, Verdict


class FeedDetector:
    def __init__(self, name: str, store: FeedStore) -> None:
        self.name = name
        self._store = store

    async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]:
        hosts = [u.host for u in urls]
        exact = await self._store.match_urls(self.name, [u.url for u in urls])
        host_hits = await first_suffix_in(self._store, self.name, hosts)
        safe_hosts = await allowlisted(self._store, hosts)
        findings: list[DetectorFinding | None] = []
        for host, meta, host_hit, allowed in zip(hosts, exact, host_hits, safe_hosts, strict=True):
            if meta is not None:
                detail = f"listed in {self.name}: {meta}" if meta else f"listed in {self.name}"
                findings.append(DetectorFinding(self.name, Verdict.MALICIOUS, detail))
            elif host_hit and allowed is None and not is_user_content(host):
                detail = f"host listed in {self.name}: {host_hit}"
                findings.append(DetectorFinding(self.name, Verdict.SUSPICIOUS, detail))
            else:
                findings.append(None)
        return findings
