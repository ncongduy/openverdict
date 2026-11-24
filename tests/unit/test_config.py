from openverdict.config import Settings


def test_defaults():
    s = Settings()
    assert s.detector_timeout_seconds == 2.0
    assert s.cache_ttl_seconds == 900
    assert s.allowlist_size == 10_000
    assert s.safe_browsing_enabled is False


def test_env_override(monkeypatch):
    monkeypatch.setenv("OPENVERDICT_CACHE_TTL_SECONDS", "60")
    assert Settings().cache_ttl_seconds == 60


def test_urlhaus_download_url():
    assert Settings().urlhaus_download_url() is None
    assert Settings(urlhaus_auth_key="k1").urlhaus_download_url() == (
        "https://urlhaus-api.abuse.ch/v2/files/exports/k1/recent.csv"
    )
    demo = "http://demo-feeds/urlhaus/recent.csv"
    assert Settings(urlhaus_url=demo).urlhaus_download_url() == demo


def test_empty_env_means_default(monkeypatch):
    # docker compose passes `${VAR:-}` as an empty string when the variable is unset.
    monkeypatch.setenv("OPENVERDICT_URLHAUS_URL", "")
    monkeypatch.setenv("OPENVERDICT_URLHAUS_AUTH_KEY", "")
    monkeypatch.setenv("OPENVERDICT_SAFE_BROWSING_ENABLED", "")
    s = Settings()
    assert s.urlhaus_url == "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
    assert s.urlhaus_auth_key is None and s.safe_browsing_enabled is False
