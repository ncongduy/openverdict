from tests.helpers import sample

CHECK, OV = "/v1/url-checks", "/v1/overrides"
LISTED = "http://malware-drop.test/payload.exe"


async def check(api, key, url):
    r = await api.post(CHECK, headers={"X-API-Key": key}, json={"urls": [url]})
    return r.json()["results"][0]


async def test_false_positive_flow(api, client_key, analyst_key, published_feeds):
    a = {"X-API-Key": analyst_key}
    assert (await check(api, client_key, LISTED))["verdict"] == "malicious"
    as_client = {"target_type": "url", "target": LISTED, "verdict": "safe"}
    r = await api.post(OV, headers={"X-API-Key": client_key}, json=as_client)
    assert r.status_code == 403
    before = sample("openverdict_override_outcomes_total", outcome="false_positive")
    r = await api.post(
        OV,
        headers=a,
        json={
            "target_type": "url",
            "target": "HTTP://Malware-Drop.test/payload.exe",
            "verdict": "safe",
            "note": "vendor file",
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert (body["engine_verdict"], body["outcome"], body["created_by"]) == (
        "malicious",
        "false_positive",
        "analyst",
    )
    assert sample("openverdict_override_outcomes_total", outcome="false_positive") == before + 1
    after = await check(api, client_key, LISTED)
    assert after["verdict"] == "safe" and after["reasons"][0]["detector"] == "override"
    assert (await api.delete(f"{OV}/{body['id']}", headers=a)).status_code == 204
    assert (await api.delete(f"{OV}/{body['id']}", headers=a)).status_code == 404
    assert (await check(api, client_key, LISTED))["verdict"] == "malicious"
    log = (await api.get("/v1/audit-log", headers=a)).json()
    assert [e["action"] for e in log[:2]] == ["override.delete", "override.create"]


async def test_domain_outcomes_and_unicode(api, client_key, analyst_key, published_feeds):
    a = {"X-API-Key": analyst_key}
    gap = await api.post(
        OV,
        headers=a,
        json={"target_type": "domain", "target": "Bücher.example", "verdict": "malicious"},
    )
    gap = gap.json()
    assert gap["outcome"] == "coverage_gap" and gap["target"] == "xn--bcher-kva.example"
    shop = await check(api, client_key, "http://shop.xn--bcher-kva.example/a")
    assert shop["verdict"] == "malicious"
    fn = await api.post(
        OV,
        headers=a,
        json={"target_type": "domain", "target": "example.com", "verdict": "malicious"},
    )
    fn = fn.json()
    assert fn["engine_verdict"] == "safe" and fn["outcome"] == "false_negative"


async def test_validation_and_list(api, analyst_key):
    a = {"X-API-Key": analyst_key}
    for bad in (
        {"target_type": "url", "target": "ftp://x.test/", "verdict": "safe"},
        {"target_type": "domain", "target": "http://x.test/", "verdict": "safe"},
    ):
        r = await api.post(OV, headers=a, json=bad)
        assert r.status_code == 422 and r.json() == {"detail": "invalid_target"}
    suspicious = {"target_type": "url", "target": "http://x.test/", "verdict": "suspicious"}
    assert (await api.post(OV, headers=a, json=suspicious)).status_code == 422
    await api.post(
        OV, headers=a, json={"target_type": "domain", "target": "x.test", "verdict": "malicious"}
    )
    await api.post(
        OV, headers=a, json={"target_type": "domain", "target": "x.test", "verdict": "safe"}
    )
    assert [o["verdict"] for o in (await api.get(OV, headers=a)).json()] == ["safe"]
