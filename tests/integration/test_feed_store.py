from openverdict.feeds.store import URLHAUS


async def test_publish_and_match(feed_store):
    await feed_store.publish(
        URLHAUS,
        {"http://a.test/x": "malware_download, 2026-11-20", "http://b.test/y": ""},
        {"a.test", "b.test"},
    )
    urls = ["http://a.test/x", "http://b.test/y", "http://c.test/"]
    assert await feed_store.match_urls(URLHAUS, urls) == ["malware_download, 2026-11-20", "", None]
    assert await feed_store.match_hosts(URLHAUS, ["a.test", "c.test"]) == [True, False]


async def test_republish_replaces_and_cleans(feed_store, valkey):
    v1 = await feed_store.publish(URLHAUS, {"http://old.test/": ""}, {"old.test"})
    v2 = await feed_store.publish(URLHAUS, {"http://new.test/": ""}, {"new.test"})
    assert v1 != v2
    assert await feed_store.match_urls(URLHAUS, ["http://old.test/"]) == [None]
    assert await feed_store.active_versions([URLHAUS]) == {URLHAUS: v2}
    assert await valkey.keys(f"feed:{URLHAUS}:{v1}:*") == []


async def test_no_active_version(feed_store):
    assert await feed_store.match_urls(URLHAUS, ["http://a.test/"]) == [None]
    assert await feed_store.match_hosts(URLHAUS, ["a.test"]) == [False]
    assert await feed_store.active_versions([URLHAUS]) == {URLHAUS: None}


async def test_large_publish_and_synced_at(feed_store):
    urls = {f"http://h{i}.test/": "" for i in range(12_000)}
    await feed_store.publish(URLHAUS, urls, set())
    assert await feed_store.match_urls(URLHAUS, ["http://h11999.test/"]) == [""]
    assert await feed_store.synced_at(URLHAUS) is None
    await feed_store.mark_synced(URLHAUS, 1700000000.5)
    assert await feed_store.synced_at(URLHAUS) == 1700000000.5
