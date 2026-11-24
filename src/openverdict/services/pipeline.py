"""The URL check pipeline: normalize → overrides → cache → detectors → combine."""

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Protocol

from redis.exceptions import RedisError

from openverdict.detectors.url.base import UrlDetector
from openverdict.logs import url_fingerprint
from openverdict.metrics import CACHE_REQUESTS, DETECTOR_DURATION, DETECTOR_FAILURES, URL_VERDICTS
from openverdict.models.overrides import OverrideMatch
from openverdict.models.url import NormalizedUrl, UrlError, normalize_url
from openverdict.models.verdict import DetectorFinding, UrlResult, Verdict, combine
from openverdict.services.cache import CachedVerdict, VerdictCache

log = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(UTC)


class OverrideLookup(Protocol):
    async def match(self, urls: Sequence[NormalizedUrl]) -> dict[str, OverrideMatch]: ...


class _Decision:
    __slots__ = ("checked_at", "degraded", "reasons", "verdict")

    def __init__(
        self,
        verdict: Verdict,
        reasons: list[DetectorFinding],
        checked_at: datetime,
        degraded: list[str] | None = None,
    ) -> None:
        self.verdict = verdict
        self.reasons = reasons
        self.checked_at = checked_at
        self.degraded = degraded or []


class UrlPipeline:
    def __init__(
        self,
        detectors: Sequence[UrlDetector],
        cache: VerdictCache,
        overrides: OverrideLookup,
        timeout_seconds: float,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._detectors = list(detectors)
        self._cache = cache
        self._overrides = overrides
        self._timeout = timeout_seconds
        self._clock = clock

    async def check(self, raw_urls: Sequence[str]) -> list[UrlResult]:
        normalized: list[NormalizedUrl | UrlError] = []
        unique: dict[str, NormalizedUrl] = {}
        for raw in raw_urls:
            try:
                url = normalize_url(raw)
            except UrlError as exc:
                normalized.append(exc)
                continue
            normalized.append(url)
            unique.setdefault(url.url, url)

        decisions = await self._decide(list(unique.values()))

        results: list[UrlResult] = []
        for raw, item in zip(raw_urls, normalized, strict=True):
            if isinstance(item, UrlError):
                URL_VERDICTS.labels(verdict="invalid").inc()
                results.append(
                    UrlResult(
                        url=raw,
                        normalized_url=None,
                        verdict=None,
                        checked_at=self._clock(),
                        error=item.code,
                    )
                )
                continue
            d = decisions[item.url]
            URL_VERDICTS.labels(verdict=d.verdict.value).inc()
            results.append(
                UrlResult(
                    url=raw,
                    normalized_url=item.url,
                    verdict=d.verdict,
                    checked_at=d.checked_at,
                    reasons=list(d.reasons),
                    degraded=list(d.degraded),
                )
            )
        log.debug("url check", extra={"urls": len(raw_urls), "unique": len(unique)})
        return results

    async def engine_verdict(self, url: NormalizedUrl) -> Verdict:
        """What the detectors alone say about one URL: no overrides, no cache."""
        findings, _ = await self._run_detectors([url])
        return combine(findings[0])

    async def _decide(self, urls: list[NormalizedUrl]) -> dict[str, _Decision]:
        decisions: dict[str, _Decision] = {}
        if not urls:
            return decisions

        for key, match in (await self._overrides.match(urls)).items():
            detail = f"analyst override #{match.id}" + (f": {match.note}" if match.note else "")
            reason = DetectorFinding("override", match.verdict, detail)
            decisions[key] = _Decision(match.verdict, [reason], self._clock())
        pending = [u for u in urls if u.url not in decisions]

        version = await self._cached(pending, decisions)
        misses = [u for u in pending if u.url not in decisions]
        if not misses:
            return decisions

        findings, degraded = await self._run_detectors(misses)
        checked_at = self._clock()
        to_cache: list[tuple[NormalizedUrl, CachedVerdict]] = []
        for url, url_findings in zip(misses, findings, strict=True):
            verdict = combine(url_findings)
            decisions[url.url] = _Decision(verdict, url_findings, checked_at, degraded)
            if verdict is Verdict.MALICIOUS:
                detectors = [f.detector for f in url_findings if f.verdict is Verdict.MALICIOUS]
                log.info("malicious url", extra={**url_fingerprint(url), "detectors": detectors})
            if not degraded:
                to_cache.append((url, CachedVerdict(verdict, url_findings, checked_at)))
        if version is not None:
            try:
                await self._cache.set_many(version, to_cache)
            except RedisError, OSError:
                CACHE_REQUESTS.labels(result="error").inc()
        return decisions

    async def _cached(
        self, pending: list[NormalizedUrl], decisions: dict[str, _Decision]
    ) -> str | None:
        """Fill decisions from the cache; returns the cache version, or None if Valkey failed."""
        if not pending:
            return None
        try:
            version = await self._cache.version()
            cached = await self._cache.get_many(version, pending)
        except RedisError, OSError:
            CACHE_REQUESTS.labels(result="error").inc()
            return None
        for url, hit in zip(pending, cached, strict=True):
            if hit is None:
                CACHE_REQUESTS.labels(result="miss").inc()
            else:
                CACHE_REQUESTS.labels(result="hit").inc()
                decisions[url.url] = _Decision(hit.verdict, hit.reasons, hit.checked_at)
        return version

    async def _run_detectors(
        self, urls: list[NormalizedUrl]
    ) -> tuple[list[list[DetectorFinding]], list[str]]:
        outputs = await asyncio.gather(*(self._run_one(d, urls) for d in self._detectors))
        degraded = sorted(
            d.name for d, out in zip(self._detectors, outputs, strict=True) if out is None
        )
        per_url: list[list[DetectorFinding]] = [[] for _ in urls]
        for out in outputs:
            if out is None:
                continue
            for i, finding in enumerate(out):
                if finding is not None:
                    per_url[i].append(finding)
        return per_url, degraded

    async def _run_one(
        self, detector: UrlDetector, urls: list[NormalizedUrl]
    ) -> list[DetectorFinding | None] | None:
        start = time.perf_counter()
        try:
            out = await asyncio.wait_for(detector.check(urls), self._timeout)
            if len(out) != len(urls):
                raise ValueError("detector returned a misaligned result")
            return out
        except TimeoutError:
            DETECTOR_FAILURES.labels(detector=detector.name, reason="timeout").inc()
            log.warning("detector timed out", extra={"detector": detector.name})
            return None
        except Exception as exc:  # noqa: BLE001 - one detector must not fail the whole check
            DETECTOR_FAILURES.labels(detector=detector.name, reason="error").inc()
            log.warning(
                "detector failed", extra={"detector": detector.name, "error": type(exc).__name__}
            )
            return None
        finally:
            DETECTOR_DURATION.labels(detector=detector.name).observe(time.perf_counter() - start)
