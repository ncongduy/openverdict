from collections.abc import AsyncIterator, Iterator

import pytest
from redis.asyncio import Redis, from_url
from testcontainers.community.redis import RedisContainer

from openverdict.feeds.store import FeedStore

VALKEY_IMAGE = "valkey/valkey:9-alpine"


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
