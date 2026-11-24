import pytest

from openverdict.detectors.url.allowlist import AllowlistDetector
from openverdict.detectors.url.feeds import FeedDetector
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding as F
from openverdict.models.verdict import Verdict as V

LISTED = "listed in urlhaus: malware_download, 2026-11-20"


@pytest.fixture
async def seeded(feed_store):
    await feed_store.publish(
        URLHAUS,
        {
            "http://malware-drop.test/payload.exe": "malware_download, 2026-11-20",
            "http://evil.github.io/a": "malware_download, 2026-11-20",
            "http://example.com/bad": "malware_download, 2026-11-20",
        },
        {"malware-drop.test", "bad-host.test", "evil.github.io", "example.com"},
    )
    await feed_store.publish(
        PHISHING_DB, {"http://secure-login.test/verify": ""}, {"phish-domain.test"}
    )
    await feed_store.publish(ALLOWLIST, {}, {"example.com", "google.com"})
    return feed_store


async def check(det, *raw):
    return await det.check([normalize_url(u) for u in raw])


async def test_feed_detector(seeded):
    d = FeedDetector(URLHAUS, seeded)
    assert await check(
        d,
        "http://malware-drop.test/payload.exe",
        "http://bad-host.test/other",
        "http://x.bad-host.test/",
        "http://evil.github.io/b",
        "http://evil.github.io/a",
        "http://example.com/other",
        "http://unlisted.test/",
    ) == [
        F("urlhaus", V.MALICIOUS, LISTED),
        F("urlhaus", V.SUSPICIOUS, "host listed in urlhaus: bad-host.test"),
        F("urlhaus", V.SUSPICIOUS, "host listed in urlhaus: bad-host.test"),
        None,
        F("urlhaus", V.MALICIOUS, LISTED),
        None,
        None,
    ]


async def test_phishing_db_empty_meta_and_domain(seeded):
    d = FeedDetector(PHISHING_DB, seeded)
    assert await check(d, "http://secure-login.test/verify", "http://login.phish-domain.test/") == [
        F("phishing_db", V.MALICIOUS, "listed in phishing_db"),
        F("phishing_db", V.SUSPICIOUS, "host listed in phishing_db: phish-domain.test"),
    ]


async def test_allowlist(seeded):
    d = AllowlistDetector(seeded)
    assert await check(
        d, "https://www.example.com/", "https://docs.google.com/x", "http://unlisted.test/"
    ) == [F("allowlist", V.SAFE, "top-sites list: example.com"), None, None]
