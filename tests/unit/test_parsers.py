import io
import zipfile
from pathlib import Path

from openverdict.feeds.parsers import (
    parse_domain_lines,
    parse_tranco,
    parse_url_lines,
    parse_urlhaus_csv,
)

FIX = Path(__file__).parents[1] / "fixtures" / "feeds"


def test_urlhaus():
    feed = parse_urlhaus_csv((FIX / "urlhaus_recent.csv").read_text())
    assert feed.urls == {
        "http://malware-drop.test/payload.exe": "malware_download, 2026-11-20",
        "http://bad-host.test/a.exe": "malware_download, 2026-11-19",
    }
    assert feed.hosts == {"malware-drop.test", "bad-host.test"}
    assert feed.skipped == 2


def test_urlhaus_plain_header_row():
    text = (
        "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-11-01 00:00:00","http://x.test/a","online","","malware_download","","l","r"\n'
    )
    assert parse_urlhaus_csv(text).urls == {"http://x.test/a": "malware_download, 2026-11-01"}


def test_url_lines():
    feed = parse_url_lines((FIX / "phishing_links.txt").read_text())
    assert feed.urls == {"http://secure-login.test/verify": ""}
    assert feed.hosts == {"secure-login.test"} and feed.skipped == 1


def test_domain_lines():
    assert parse_domain_lines((FIX / "phishing_domains.txt").read_text()) == {
        "phish-domain.test",
        "xn--bcher-phish-thb.test",
    }


def test_tranco_plain_and_zip():
    csv = b"1,example.com\n2,example.org\n3,example.net\n"
    assert parse_tranco(csv, 2) == ["example.com", "example.org"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", csv)
    assert parse_tranco(buf.getvalue(), 3) == ["example.com", "example.org", "example.net"]
