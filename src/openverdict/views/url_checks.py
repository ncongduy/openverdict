"""Request and response schemas for URL checks (the View in MVC)."""

from datetime import datetime

from pydantic import BaseModel, Field

from openverdict.models.verdict import UrlResult, Verdict

SYNC_MAX_URLS = 100


class UrlCheckRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=SYNC_MAX_URLS)


class ReasonView(BaseModel):
    detector: str
    verdict: Verdict
    detail: str


class UrlResultView(BaseModel):
    url: str
    normalized_url: str | None
    verdict: Verdict | None
    reasons: list[ReasonView]
    degraded: list[str]
    checked_at: datetime
    error: str | None


class UrlCheckResponse(BaseModel):
    results: list[UrlResultView]


def result_to_view(result: UrlResult) -> UrlResultView:
    return UrlResultView(
        url=result.url,
        normalized_url=result.normalized_url,
        verdict=result.verdict,
        reasons=[
            ReasonView(detector=r.detector, verdict=r.verdict, detail=r.detail)
            for r in result.reasons
        ],
        degraded=result.degraded,
        checked_at=result.checked_at,
        error=result.error,
    )
