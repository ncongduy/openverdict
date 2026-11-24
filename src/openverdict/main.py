"""FastAPI application factory."""

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from openverdict.config import Settings
from openverdict.controllers import health, url_checks
from openverdict.logs import request_id_var
from openverdict.metrics import HTTP_DURATION
from openverdict.resources import build_resources

MAX_BODY_BYTES = 25 * 1024 * 1024


async def _observe(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Request ID in and out, body-size limit, and latency metrics by route template."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    token = request_id_var.set(request_id)
    start = time.perf_counter()
    try:
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > MAX_BODY_BYTES:
            response: Response = JSONResponse({"detail": "body_too_large"}, status_code=413)
        else:
            response = await call_next(request)
    finally:
        request_id_var.reset(token)
    route = getattr(request.scope.get("route"), "path", "unmatched")
    HTTP_DURATION.labels(request.method, route, str(response.status_code)).observe(
        time.perf_counter() - start
    )
    response.headers["X-Request-ID"] = request_id
    return response


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resources = await build_resources(app_settings)
        app.state.resources = resources
        try:
            yield
        finally:
            await resources.aclose()

    app = FastAPI(title="openverdict", version="0.1.0", lifespan=lifespan)
    app.middleware("http")(_observe)
    app.include_router(health.router)
    app.include_router(url_checks.router)
    return app
