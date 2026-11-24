import asyncio
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from redis.asyncio import Redis, from_url
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine as sa_create_async_engine
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from openverdict.feeds.store import FeedStore
from openverdict.models.db import create_engine, create_sessionmaker, run_migrations

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
