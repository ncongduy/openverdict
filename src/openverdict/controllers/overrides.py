"""Analyst overrides and the audit log (analyst role only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from openverdict.controllers.deps import get_resources, require
from openverdict.models.api_keys import Principal, Role
from openverdict.models.overrides import TargetType
from openverdict.models.verdict import Verdict
from openverdict.resources import Resources
from openverdict.services.overrides import InvalidTarget
from openverdict.views.overrides import AuditEntryView, OverrideCreateRequest, OverrideView

router = APIRouter(prefix="/v1", tags=["overrides"])
Analyst = Annotated[Principal, Depends(require(Role.ANALYST))]
Res = Annotated[Resources, Depends(get_resources)]


@router.post("/overrides", status_code=201)
async def create_override(
    body: OverrideCreateRequest, analyst: Analyst, resources: Res
) -> OverrideView:
    try:
        record = await resources.override_service.create(
            analyst, TargetType(body.target_type), body.target, Verdict(body.verdict), body.note
        )
    except InvalidTarget as exc:
        raise HTTPException(status_code=422, detail="invalid_target") from exc
    return OverrideView.of(record)


@router.get("/overrides")
async def list_overrides(_analyst: Analyst, resources: Res) -> list[OverrideView]:
    return [OverrideView.of(r) for r in await resources.override_service.list_active()]


@router.delete("/overrides/{override_id}", status_code=204)
async def delete_override(override_id: int, analyst: Analyst, resources: Res) -> Response:
    if not await resources.override_service.delete(analyst, override_id):
        raise HTTPException(status_code=404, detail="not_found")
    return Response(status_code=204)


@router.get("/audit-log")
async def audit_log(
    _analyst: Analyst,
    resources: Res,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditEntryView]:
    entries = await resources.override_service.audit_log(limit, offset)
    return [AuditEntryView.of(e) for e in entries]
