import pytest

from openverdict.detectors.url.heuristics import (
    DEFAULT_BRANDS,
    DEFAULT_RISKY_TLDS,
    HeuristicsDetector,
    score_url,
)
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding, Verdict


def names(raw):
    return {s.name for s in score_url(normalize_url(raw), DEFAULT_BRANDS, DEFAULT_RISKY_TLDS)}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://192.0.2.10/login", {"ip_literal_host"}),
        ("http://3232235777/", {"ip_literal_host"}),
        ("http://paypa1.test/", {"brand_lookalike"}),
        ("http://paypal-login.test/", {"brand_combo"}),
        ("http://paypal.com/", set()),
        ("http://a.b.c.d.e.evil.test/", {"deep_subdomains"}),
        ("http://a.test/" + "x" * 200, {"long_url"}),
        ("http://shop.zip/", {"risky_tld"}),
        ("https://www.example.com/", set()),
    ],
)
def test_signals(raw, expected):
    assert names(raw) == expected


def test_homoglyph_and_userinfo():
    homoglyph = names("http://pаypal.test/")
    assert {"punycode_host", "mixed_script_host", "brand_lookalike"} <= homoglyph
    assert "at_in_authority" in names("http://paypal.com@evil.test/")


async def test_detector():
    d = HeuristicsDetector()
    urls = ("http://192.0.2.10/", "http://shop.zip/", "http://example.com/")
    hit, low, clean = await d.check([normalize_url(u) for u in urls])
    assert hit == DetectorFinding("heuristics", Verdict.SUSPICIOUS, "ip_literal_host+3 (score 3)")
    assert low is None and clean is None
