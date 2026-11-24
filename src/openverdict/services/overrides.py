"""Analyst overrides: normalize the target, record what the engine would have said, audit it."""

import logging

from redis.exceptions import RedisError

from openverdict.metrics import OVERRIDE_OUTCOMES
from openverdict.models.api_keys import Principal
from openverdict.models.overrides import AuditRecord, OverrideRecord, OverrideRepo, TargetType
from openverdict.models.url import UrlError, normalize_domain, normalize_url
from openverdict.models.verdict import Verdict, classify_override
from openverdict.services.cache import VerdictCache
from openverdict.services.pipeline import UrlPipeline

log = logging.getLogger(__name__)


class InvalidTarget(Exception):
    pass


class OverrideService:
    def __init__(self, repo: OverrideRepo, pipeline: UrlPipeline, cache: VerdictCache) -> None:
        self._repo = repo
        self._pipeline = pipeline
        self._cache = cache

    async def create(
        self, actor: Principal, target_type: TargetType, target: str, verdict: Verdict, note: str
    ) -> OverrideRecord:
        try:
            if target_type is TargetType.URL:
                probe = normalize_url(target)
                value = probe.url
            else:
                value = normalize_domain(target)
                probe = normalize_url(f"https://{value}/")
        except UrlError as exc:
            raise InvalidTarget(target_type.value) from exc
        engine_verdict = await self._pipeline.engine_verdict(probe)
        outcome = classify_override(engine_verdict, verdict)
        record = await self._repo.create(
            actor, target_type, value, verdict, note, engine_verdict, outcome
        )
        OVERRIDE_OUTCOMES.labels(outcome=outcome.value).inc()
        await self._bump_cache()
        return record

    async def delete(self, actor: Principal, override_id: int) -> bool:
        deleted = await self._repo.deactivate(actor, override_id)
        if deleted:
            await self._bump_cache()
        return deleted

    async def list_active(self) -> list[OverrideRecord]:
        return await self._repo.list_active()

    async def audit_log(self, limit: int, offset: int) -> list[AuditRecord]:
        return await self._repo.audit_log(limit, offset)

    async def _bump_cache(self) -> None:
        # Overrides are read before the cache, so a failed bump cannot hide an override.
        try:
            await self._cache.bump_overrides()
        except RedisError, OSError:
            log.warning("could not bump the overrides cache version")
