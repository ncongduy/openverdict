"""Google Safe Browsing Lookup API (opt-in: sends the checked URLs to Google)."""

import itertools
from collections.abc import Sequence

import httpx

from openverdict.models.url import NormalizedUrl
from openverdict.models.verdict import DetectorFinding, Verdict

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
MAX_ENTRIES_PER_REQUEST = 500
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


class SafeBrowsingDetector:
    name = "safe_browsing"

    def __init__(
        self, http: httpx.AsyncClient, api_key: str, endpoint: str = SAFE_BROWSING_URL
    ) -> None:
        self._http = http
        self._api_key = api_key
        self._endpoint = endpoint

    async def check(self, urls: Sequence[NormalizedUrl]) -> list[DetectorFinding | None]:
        threats: dict[str, str] = {}
        for batch in itertools.batched(
            (u.url for u in urls), MAX_ENTRIES_PER_REQUEST, strict=False
        ):
            threats.update(await self._lookup(batch))
        return [
            DetectorFinding(self.name, Verdict.MALICIOUS, f"safe browsing: {threats[u.url]}")
            if u.url in threats
            else None
            for u in urls
        ]

    async def _lookup(self, batch: Sequence[str]) -> dict[str, str]:
        body = {
            "client": {"clientId": "openverdict", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url} for url in batch],
            },
        }
        response = await self._http.post(self._endpoint, params={"key": self._api_key}, json=body)
        response.raise_for_status()
        matches = response.json().get("matches", [])
        return {m["threat"]["url"]: m["threatType"] for m in matches}
