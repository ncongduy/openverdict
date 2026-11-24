from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.overrides import OverrideRepo
from openverdict.models.overrides import TargetType as T
from openverdict.models.url import normalize_url
from openverdict.models.verdict import OverrideOutcome as O
from openverdict.models.verdict import Verdict as V

GAP = (V.UNKNOWN, O.COVERAGE_GAP)


async def setup(db):
    analyst, _ = await ApiKeyRepo(db).create("ana", Role.ANALYST)
    return OverrideRepo(db), analyst


async def test_match_precedence(db):
    repo, a = await setup(db)
    await repo.create(a, T.DOMAIN, "evil.test", V.MALICIOUS, "", *GAP)
    sub = await repo.create(a, T.DOMAIN, "ok.evil.test", V.SAFE, "vetted", *GAP)
    exact = await repo.create(a, T.URL, "http://ok.evil.test/bad", V.MALICIOUS, "", *GAP)
    urls = [
        normalize_url(u)
        for u in (
            "http://x.evil.test/",
            "http://a.ok.evil.test/",
            "http://ok.evil.test/bad",
            "http://other.test/",
        )
    ]
    m = await repo.match(urls)
    assert m["http://x.evil.test/"].verdict is V.MALICIOUS
    assert m["http://a.ok.evil.test/"].id == sub.id
    assert m["http://a.ok.evil.test/"].note == "vetted"
    assert m["http://ok.evil.test/bad"].id == exact.id
    assert "http://other.test/" not in m


async def test_replace_and_delete_with_audit(db):
    repo, a = await setup(db)
    first = await repo.create(a, T.DOMAIN, "evil.test", V.MALICIOUS, "", *GAP)
    second = await repo.create(a, T.DOMAIN, "evil.test", V.SAFE, "fp", *GAP)
    assert [r.id for r in await repo.list_active()] == [second.id]
    assert await repo.deactivate(a, second.id) is True
    assert await repo.deactivate(a, second.id) is False
    assert await repo.match([normalize_url("http://evil.test/")]) == {}
    log = await repo.audit_log(limit=10, offset=0)
    assert [e.action for e in log] == ["override.delete", "override.create", "override.create"]
    assert log[1].before["id"] == first.id and log[1].after["verdict"] == "safe"
    assert log[0].actor == "ana" and log[0].after is None
