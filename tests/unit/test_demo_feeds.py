from pathlib import Path

from openverdict.feeds.parsers import (
    parse_domain_lines,
    parse_tranco,
    parse_url_lines,
    parse_urlhaus_csv,
)

DEMO = Path(__file__).parents[2] / "deploy" / "compose" / "demo-feeds"


def test_demo_feeds_parse_with_real_parsers():
    urlhaus = parse_urlhaus_csv((DEMO / "urlhaus/recent.csv").read_text())
    assert "http://malware-drop.test/payload.exe" in urlhaus.urls
    assert "bad-host.test" in urlhaus.hosts
    links = parse_url_lines((DEMO / "phishing/links.txt").read_text())
    assert links.urls == {"http://secure-login.test/verify": ""}
    assert parse_domain_lines((DEMO / "phishing/domains.txt").read_text()) == {"phish-domain.test"}
    tranco = parse_tranco((DEMO / "tranco/top-1m.csv").read_bytes(), 10)
    assert tranco == ["example.com", "example.org", "example.net"]
