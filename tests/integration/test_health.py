import httpx

from openverdict.main import create_app


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
