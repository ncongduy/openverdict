import asyncio

import pytest
from redis.asyncio import from_url

from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.overrides import OverrideRepo, TargetType
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding as F
from openverdict.models.verdict import OverrideOutcome
from openverdict.models.verdict import Verdict as V
from openverdict.services.cache import VerdictCache
from openverdict.services.pipeline import UrlPipeline
from tests.helpers import sample


class Fake:
    def __init__(self, name, hits=None, delay=0.0, boom=False):
        self.name, self.hits, self.delay, self.boom, self.calls = name, hits or {}, delay, boom, []

    async def check(self, urls):
        self.calls.append([u.url for u in urls])
        await asyncio.sleep(self.delay)
        if self.boom:
            raise RuntimeError("boom")
        return [self.hits.get(u.url) for u in urls]


BAD = F("feed", V.MALICIOUS, "listed")
SUS = F("heur", V.SUSPICIOUS, "score 3")


@pytest.fixture
async def make(valkey, db):
    def _make(*dets, timeout=1.0, cache_valkey=None):
        cache = VerdictCache(cache_valkey or valkey, 900)
        return UrlPipeline(list(dets), cache, OverrideRepo(db), timeout)

    return _make


async def test_order_errors_combine(make):
    p = make(Fake("feed", {"http://a.test/": BAD}), Fake("heur", {"http://a.test/": SUS}))
    r = await p.check(["http://a.test/", "ftp://x.test/", "http://b.test/"])
    assert [x.verdict for x in r] == [V.MALICIOUS, None, V.UNKNOWN]
    assert r[0].reasons == [BAD, SUS]
    assert r[1].error == "unsupported_scheme" and r[2].reasons == []


async def test_duplicates_checked_once(make):
    det = Fake("feed")
    r = await make(det).check(["http://a.test/x", "HTTP://A.test/x"])
    assert len(r) == 2 and det.calls == [["http://a.test/x"]]


async def test_timeout_and_error_degrade(make):
    before = sample("openverdict_detector_failures_total", detector="slow", reason="timeout")
    p = make(
        Fake("slow", delay=1.0),
        Fake("bad", boom=True),
        Fake("heur", {"http://a.test/": SUS}),
        timeout=0.05,
    )
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.SUSPICIOUS and r.degraded == ["bad", "slow"]
    after = sample("openverdict_detector_failures_total", detector="slow", reason="timeout")
    assert after == before + 1


async def test_cache_hit_and_invalidation(make, valkey):
    det = Fake("feed", {"http://a.test/": BAD})
    p = make(det)
    await p.check(["http://a.test/"])
    hits = sample("openverdict_cache_requests_total", result="hit")
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.MALICIOUS and len(det.calls) == 1
    assert sample("openverdict_cache_requests_total", result="hit") == hits + 1
    await VerdictCache(valkey, 900).bump_overrides()
    await p.check(["http://a.test/"])
    assert len(det.calls) == 2


async def test_degraded_not_cached(make):
    det = Fake("feed", boom=True)
    p = make(det)
    await p.check(["http://a.test/"])
    await p.check(["http://a.test/"])
    assert len(det.calls) == 2


async def test_override_wins_and_skips_detectors(make, db):
    a, _ = await ApiKeyRepo(db).create("ana", Role.ANALYST)
    o = await OverrideRepo(db).create(
        a,
        TargetType.DOMAIN,
        "a.test",
        V.SAFE,
        "vetted",
        V.MALICIOUS,
        OverrideOutcome.FALSE_POSITIVE,
    )
    det = Fake("feed", {"http://x.a.test/": BAD})
    p = make(det)
    [r] = await p.check(["http://x.a.test/"])
    assert r.verdict is V.SAFE
    assert r.reasons == [F("override", V.SAFE, f"analyst override #{o.id}: vetted")]
    assert det.calls == []
    assert await p.engine_verdict(normalize_url("http://x.a.test/")) is V.MALICIOUS


async def test_valkey_down_still_answers(make):
    dead = from_url("redis://127.0.0.1:1/0", decode_responses=True, socket_connect_timeout=0.2)
    p = make(Fake("heur", {"http://a.test/": SUS}), cache_valkey=dead)
    [r] = await p.check(["http://a.test/"])
    assert r.verdict is V.SUSPICIOUS
    await dead.aclose()
