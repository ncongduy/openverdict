"""Liveness, readiness and Prometheus endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from openverdict.controllers.deps import get_resources
from openverdict.resources import Resources

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(resources: Annotated[Resources, Depends(get_resources)]) -> JSONResponse:
    status = {"postgres": "ok", "valkey": "ok"}
    try:
        async with resources.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - any failure means not ready
        status["postgres"] = "error"
    try:
        await resources.valkey.ping()
    except Exception:  # noqa: BLE001 - any failure means not ready
        status["valkey"] = "error"
    ready = all(value == "ok" for value in status.values())
    return JSONResponse(status, status_code=200 if ready else 503)


@router.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
