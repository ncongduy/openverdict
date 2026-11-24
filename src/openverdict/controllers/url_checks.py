"""Synchronous URL checks (the Controller in MVC)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from openverdict.controllers.deps import get_resources, require
from openverdict.models.api_keys import Principal, Role
from openverdict.resources import Resources
from openverdict.views.url_checks import UrlCheckRequest, UrlCheckResponse, result_to_view

router = APIRouter(prefix="/v1", tags=["url-checks"])


@router.post("/url-checks")
async def check_urls(
    body: UrlCheckRequest,
    _principal: Annotated[Principal, Depends(require(Role.CLIENT, Role.ANALYST))],
    resources: Annotated[Resources, Depends(get_resources)],
) -> UrlCheckResponse:
    results = await resources.pipeline.check(body.urls)
    return UrlCheckResponse(results=[result_to_view(r) for r in results])
