from openverdict.detectors.url.user_content import is_user_content


def test_user_content():
    assert is_user_content("evil.github.io") and is_user_content("github.io")
    assert is_user_content("docs.google.com")
    assert not is_user_content("www.google.com") and not is_user_content("github.com")
