import hashlib

import pytest

from openverdict.models.url import UrlError, host_suffixes, normalize_domain, normalize_url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.COM:80/a?b=1#frag", "http://example.com/a?b=1"),
        ("https://example.com:443/", "https://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        ("http://example.com", "http://example.com/"),
        ("http://example.com./p", "http://example.com/p"),
        ("  http://a.test/x  ", "http://a.test/x"),
        ("http://user:pw@a.test/", "http://user:pw@a.test/"),
        ("http://[::1]:8080/", "http://[::1]:8080/"),
    ],
)
def test_normalize(raw, expected):
    assert normalize_url(raw).url == expected


def test_idn_host():
    n = normalize_url("http://Bücher.example/")
    assert (n.host, n.host_unicode, n.url) == (
        "xn--bcher-kva.example",
        "bücher.example",
        "http://xn--bcher-kva.example/",
    )
    assert normalize_url("http://xn--bcher-kva.example/").host_unicode == "bücher.example"


def test_userinfo_and_hash():
    n = normalize_url("http://paypal.com@Evil.test/")
    assert n.has_userinfo and n.host == "evil.test"
    assert normalize_url("HTTP://A.test").sha256 == hashlib.sha256(b"http://a.test/").hexdigest()


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("ftp://files.test/x", "unsupported_scheme"),
        ("javascript:alert(1)", "unsupported_scheme"),
        ("example.com/path", "invalid_url"),
        ("http://", "invalid_url"),
        ("not a url", "invalid_url"),
        ("http://exa mple.test/", "invalid_url"),
        ("http://a.test:99999/", "invalid_url"),
        ("http://a.test/" + "x" * 2048, "too_long"),
    ],
)
def test_rejects(raw, code):
    with pytest.raises(UrlError) as exc:
        normalize_url(raw)
    assert exc.value.code == code


def test_normalize_domain():
    assert normalize_domain("Bücher.Example.") == "xn--bcher-kva.example"
    for bad in ("http://x.test/", "a b.test", "", "x.test/path"):
        with pytest.raises(UrlError):
            normalize_domain(bad)


def test_host_suffixes():
    assert host_suffixes("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert host_suffixes("example.com") == ["example.com"]
    assert host_suffixes("192.0.2.1") == ["192.0.2.1"]
