import json

import httpx
import pytest
import respx

from openverdict.detectors.url.safe_browsing import SAFE_BROWSING_URL, SafeBrowsingDetector
from openverdict.models.url import normalize_url
from openverdict.models.verdict import DetectorFinding, Verdict


@respx.mock
async def test_matches_and_batching():
    def reply(request):
        urls = [e["url"] for e in json.loads(request.content)["threatInfo"]["threatEntries"]]
        assert len(urls) <= 500
        hit = [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": u}} for u in urls if "phish" in u
        ]
        return httpx.Response(200, json={"matches": hit} if hit else {})

    route = respx.post(SAFE_BROWSING_URL).mock(side_effect=reply)
    urls = [normalize_url(f"http://h{i}.test/") for i in range(600)]
    urls.append(normalize_url("http://phish.test/"))
    async with httpx.AsyncClient() as http:
        out = await SafeBrowsingDetector(http, "k").check(urls)
    assert route.call_count == 2
    expected = DetectorFinding(
        "safe_browsing", Verdict.MALICIOUS, "safe browsing: SOCIAL_ENGINEERING"
    )
    assert out[-1] == expected
    assert out[:600] == [None] * 600


@respx.mock
async def test_http_error_raises():
    respx.post(SAFE_BROWSING_URL).respond(403)
    async with httpx.AsyncClient() as http:
        with pytest.raises(httpx.HTTPStatusError):
            await SafeBrowsingDetector(http, "k").check([normalize_url("http://a.test/")])
