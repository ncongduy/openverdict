from openverdict.detectors.url.user_content import is_user_content


def test_user_content():
    assert is_user_content("evil.github.io") and is_user_content("github.io")
    assert is_user_content("docs.google.com")
    assert not is_user_content("www.google.com") and not is_user_content("github.com")


def test_shorteners_and_hosted_content_are_never_allowlisted():
    # Their popularity says nothing about where a link leads.
    for host in ("bit.ly", "t.co", "tinyurl.com", "lnkd.in", "linktr.ee", "is.gd"):
        assert is_user_content(host), host
    for host in ("firebasestorage.googleapis.com", "script.google.com", "x.translate.goog"):
        assert is_user_content(host), host
