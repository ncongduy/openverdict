import httpx

from openverdict.main import create_app
from tests.helpers import sample


async def test_health_ready_metrics(api):
    assert (await api.get("/healthz")).json() == {"status": "ok"}
    assert (await api.get("/readyz")).json() == {"postgres": "ok", "valkey": "ok"}
    assert "openverdict_http_request_duration_seconds" in (await api.get("/metrics")).text


async def test_ready_fails_without_valkey(settings):
    app = create_app(settings.model_copy(update={"valkey_url": "redis://127.0.0.1:1/0"}))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            r = await client.get("/readyz")
    assert r.status_code == 503 and r.json()["valkey"] == "error"


async def test_unhandled_error_is_counted_and_answered(app, api):
    async def boom() -> None:
        raise RuntimeError("database down")

    app.add_api_route("/boom", boom)
    before = sample(
        "openverdict_http_request_duration_seconds_count", method="GET", route="/boom", status="500"
    )
    r = await api.get("/boom", headers={"X-Request-ID": "req-500"})
    assert r.status_code == 500 and r.json() == {"detail": "internal_error"}
    assert r.headers["X-Request-ID"] == "req-500"
    after = sample(
        "openverdict_http_request_duration_seconds_count", method="GET", route="/boom", status="500"
    )
    assert after == before + 1
