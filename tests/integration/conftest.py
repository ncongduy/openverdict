import asyncio
import uuid
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import FastAPI
from redis.asyncio import Redis, from_url
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine as sa_create_async_engine
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from openverdict.config import Settings
from openverdict.feeds.store import ALLOWLIST, PHISHING_DB, URLHAUS, FeedStore
from openverdict.main import create_app
from openverdict.models.api_keys import ApiKeyRepo, Role
from openverdict.models.db import create_engine, create_sessionmaker, run_migrations
from openverdict.resources import Resources

VALKEY_IMAGE = "valkey/valkey:9-alpine"
POSTGRES_IMAGE = "postgres:18-alpine"


@pytest.fixture(scope="session")
def valkey_url() -> Iterator[str]:
    with RedisContainer(VALKEY_IMAGE) as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest.fixture
async def valkey(valkey_url: str) -> AsyncIterator[Redis]:
    client = from_url(valkey_url, decode_responses=True)
    await client.flushdb()
    yield client
    await client.aclose()


@pytest.fixture
async def feed_store(valkey: Redis) -> FeedStore:
    return FeedStore(valkey)


@pytest.fixture(scope="session")
def pg_template_url() -> Iterator[str]:
    """Migrated database used only as a template; tests never connect to it directly."""
    with PostgresContainer(POSTGRES_IMAGE, driver="asyncpg") as container:
        url = container.get_connection_url()
        run_migrations(url)
        yield url


async def _clone_database(template_url: str, name: str) -> None:
    template = make_url(template_url)
    admin = sa_create_async_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}" TEMPLATE "{template.database}"'))
    await admin.dispose()


@pytest.fixture
def db_url(pg_template_url: str) -> str:
    """A fresh, migrated database per test, cloned from the template."""
    name = f"t_{uuid.uuid4().hex[:12]}"
    asyncio.run(_clone_database(pg_template_url, name))
    return make_url(pg_template_url).set(database=name).render_as_string(hide_password=False)


@pytest.fixture
async def db(db_url: str) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_engine(db_url)
    yield create_sessionmaker(engine)
    await engine.dispose()


@pytest.fixture
def settings(db_url: str, valkey_url: str) -> Settings:
    return Settings(
        database_url=db_url,
        valkey_url=valkey_url,
        urlhaus_url="http://feeds.test/urlhaus.csv",
        phishing_db_links_url="http://feeds.test/links.txt",
        phishing_db_domains_url="http://feeds.test/domains.txt",
        tranco_url="http://feeds.test/tranco.csv",
        detector_timeout_seconds=1.0,
    )


@pytest.fixture
async def app(settings: Settings, valkey: Redis) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def api(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def resources(app: FastAPI) -> Resources:
    res: Resources = app.state.resources
    return res


@pytest.fixture
async def client_key(db: async_sessionmaker[AsyncSession]) -> str:
    _, key = await ApiKeyRepo(db).create("client", Role.CLIENT)
    return key


@pytest.fixture
async def analyst_key(db: async_sessionmaker[AsyncSession]) -> str:
    _, key = await ApiKeyRepo(db).create("analyst", Role.ANALYST)
    return key


@pytest.fixture
async def published_feeds(feed_store: FeedStore) -> FeedStore:
    await feed_store.publish(
        URLHAUS,
        {
            "http://malware-drop.test/payload.exe": "malware_download, 2026-11-20",
            "http://evil.github.io/a": "malware_download, 2026-11-20",
            "http://example.com/bad": "malware_download, 2026-11-20",
        },
        {"malware-drop.test", "bad-host.test", "evil.github.io", "example.com"},
    )
    await feed_store.publish(
        PHISHING_DB, {"http://secure-login.test/verify": ""}, {"phish-domain.test"}
    )
    await feed_store.publish(ALLOWLIST, {}, {"example.com", "google.com"})
    return feed_store
