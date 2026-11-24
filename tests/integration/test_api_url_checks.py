import logging

from tests.helpers import sample

URL = "/v1/url-checks"


async def test_auth(api, client_key):
    body = {"urls": ["http://a.test/"]}
    assert (await api.post(URL, json=body)).status_code == 401
    assert (await api.post(URL, json=body, headers={"X-API-Key": "ov_nope"})).status_code == 401
    assert (await api.post(URL, json=body, headers={"X-API-Key": client_key})).status_code == 200


async def test_verdicts(api, client_key, published_feeds):
    before = sample("openverdict_url_verdicts_total", verdict="malicious")
    urls = [
        "http://malware-drop.test/payload.exe",
        "https://www.example.com/",
        "http://paypa1.test/login",
        "http://unlisted.test/",
        "ftp://files.test/x",
    ]
    r = await api.post(URL, headers={"X-API-Key": client_key}, json={"urls": urls})
    body = r.json()["results"]
    assert [x["verdict"] for x in body] == ["malicious", "safe", "suspicious", "unknown", None]
    assert body[0]["reasons"][0] == {
        "detector": "urlhaus",
        "verdict": "malicious",
        "detail": "listed in urlhaus: malware_download, 2026-11-20",
    }
    assert body[4]["error"] == "unsupported_scheme" and body[0]["degraded"] == []
    assert sample("openverdict_url_verdicts_total", verdict="malicious") == before + 1


async def test_limits(api, client_key):
    h = {"X-API-Key": client_key}
    assert (await api.post(URL, headers=h, json={"urls": []})).status_code == 422
    too_many = {"urls": ["http://a.test/"] * 101}
    assert (await api.post(URL, headers=h, json=too_many)).status_code == 422
    too_big = b"x" * (25 * 1024 * 1024 + 1)
    big_headers = {**h, "Content-Type": "application/json"}
    assert (await api.post(URL, headers=big_headers, content=too_big)).status_code == 413


async def test_no_url_in_logs_and_request_id(api, client_key, caplog):
    secret = "http://a.test/reset?token=secret-reset-token-123"
    with caplog.at_level(logging.DEBUG):
        r = await api.post(
            URL,
            headers={"X-API-Key": client_key, "X-Request-ID": "req-1"},
            json={"urls": [secret]},
        )
    assert r.headers["X-Request-ID"] == "req-1"
    dumped = caplog.text + "".join(str(vars(rec)) for rec in caplog.records)
    assert "secret-reset-token-123" not in dumped


async def test_control_character_item_does_not_fail_batch(api, client_key):
    urls = ["http://ok.test/", "http://a.test/x\u0000y"]
    r = await api.post(URL, headers={"X-API-Key": client_key}, json={"urls": urls})
    assert r.status_code == 200
    assert [x["error"] for x in r.json()["results"]] == [None, "invalid_url"]
