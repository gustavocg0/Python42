import fakeredis.aioredis
import pytest


@pytest.fixture
async def redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()
