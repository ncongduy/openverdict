import logging

import httpx
import pytest
import respx

from openverdict.config import Settings
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS
from openverdict.feeds.sync import FeedSyncer, build_sources
from tests.helpers import sample

KEY = "sekret-key-123"
URLHAUS_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
CSV = (
    '"1","2026-11-20 10:00:00","http://malware-drop.test/payload.exe",'
    '"online","","malware_download","","l","r"\n'
)


@pytest.fixture
def sync_settings():
    return Settings(
        urlhaus_auth_key=KEY,
        phishing_db_links_url="http://feeds.test/links.txt",
        phishing_db_domains_url="http://feeds.test/domains.txt",
        tranco_url="http://feeds.test/tranco.csv",
        allowlist_size=2,
    )


def by_name(settings):
    return {s.name: s for s in build_sources(settings)}


@pytest.fixture
async def syncer(feed_store, valkey, sync_settings):
    async with httpx.AsyncClient() as http:
        yield FeedSyncer(feed_store, valkey, http, build_sources(sync_settings))


@respx.mock
async def test_urlhaus_sync(syncer, feed_store, sync_settings):
    respx.get(URLHAUS_URL).respond(text=CSV)
    assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is True
    assert await feed_store.match_urls(URLHAUS, ["http://malware-drop.test/payload.exe"]) == [
        "malware_download, 2026-11-20"
    ]
    assert await feed_store.synced_at(URLHAUS) is not None
    assert sample("openverdict_feed_entries", feed=URLHAUS, kind="urls") == 1


@respx.mock
@pytest.mark.parametrize(
    "response", [httpx.Response(500), httpx.Response(200, text="<html>oops</html>")]
)
async def test_failure_keeps_old_and_hides_key(syncer, feed_store, sync_settings, caplog, response):
    await feed_store.publish(URLHAUS, {"http://old.test/": ""}, {"old.test"})
    respx.get(URLHAUS_URL).mock(return_value=response)
    before = sample("openverdict_feed_sync_failures_total", feed=URLHAUS)
    with caplog.at_level(logging.DEBUG):
        assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is False
    assert await feed_store.match_urls(URLHAUS, ["http://old.test/"]) == [""]
    assert sample("openverdict_feed_sync_failures_total", feed=URLHAUS) == before + 1
    assert KEY not in caplog.text and "urlhaus-api.abuse.ch" not in caplog.text


@respx.mock
async def test_lock_held_skips(syncer, valkey, sync_settings):
    route = respx.get(URLHAUS_URL).respond(text=CSV)
    await valkey.set(f"lock:feed:{URLHAUS}", "other", ex=600)
    assert await syncer.sync(by_name(sync_settings)[URLHAUS]) is False
    assert not route.called


def test_build_sources_without_key():
    assert URLHAUS not in by_name(Settings())
    assert URLHAUS in by_name(Settings(urlhaus_url="http://demo-feeds/urlhaus/recent.csv"))


@respx.mock
async def test_phishing_db_and_tranco(syncer, feed_store, sync_settings):
    respx.get("http://feeds.test/links.txt").respond(text="http://secure-login.test/verify\n")
    respx.get("http://feeds.test/domains.txt").respond(text="phish-domain.test\n")
    respx.get("http://feeds.test/tranco.csv").respond(
        content=b"1,example.com\n2,example.org\n3,example.net\n"
    )
    assert await syncer.sync(by_name(sync_settings)[PHISHING_DB])
    assert await syncer.sync(by_name(sync_settings)[ALLOWLIST])
    hosts = ["phish-domain.test", "secure-login.test"]
    assert await feed_store.match_hosts(PHISHING_DB, hosts) == [True, True]
    assert await feed_store.match_hosts(ALLOWLIST, ["example.org", "example.net"]) == [True, False]


@respx.mock
async def test_sync_due(syncer, feed_store):
    respx.get(URLHAUS_URL).respond(text=CSV)
    respx.get("http://feeds.test/links.txt").respond(text="http://secure-login.test/verify\n")
    respx.get("http://feeds.test/domains.txt").respond(text="")
    tranco = respx.get("http://feeds.test/tranco.csv").respond(content=b"1,example.com\n")
    await feed_store.mark_synced(ALLOWLIST, 1_000_000.0)
    await syncer.sync_due(now=1_000_010.0)
    assert await feed_store.synced_at(URLHAUS) is not None
    assert not tranco.called
