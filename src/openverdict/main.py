"""FastAPI application factory."""

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from openverdict.config import Settings
from openverdict.controllers import health, jobs, overrides, url_checks
from openverdict.logs import request_id_var
from openverdict.metrics import HTTP_DURATION
from openverdict.resources import build_resources

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 25 * 1024 * 1024


class BodyLimit:
    """Reject request bodies over the limit, whether or not they declare Content-Length.

    Chunked bodies are counted as they arrive, so an unauthenticated client cannot make the
    app buffer an unbounded body before authentication runs.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        length = headers.get(b"content-length", b"").decode()
        if length.isdigit() and int(length) > self.max_bytes:
            response = JSONResponse({"detail": "body_too_large"}, status_code=413)
            await response(scope, receive, send)
            return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail="body_too_large")
            return message

        await self.app(scope, limited_receive, send)


async def _observe(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Request ID in and out, and latency metrics by route template."""
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    token = request_id_var.set(request_id)
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:  # noqa: BLE001 - answer and count it, so 5xx shows on the dashboard
        log.error("unhandled error", extra={"error": type(exc).__name__})
        response = JSONResponse({"detail": "internal_error"}, status_code=500)
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
    app.add_middleware(BodyLimit)
    app.middleware("http")(_observe)  # added last, so it wraps BodyLimit and sees its 413s
    app.include_router(health.router)
    app.include_router(url_checks.router)
    app.include_router(overrides.router)
    app.include_router(jobs.router)
    return app
