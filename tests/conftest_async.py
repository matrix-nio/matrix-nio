import pytest

from nio import AsyncClient
from aioresponses import aioresponses


@pytest.fixture
async def async_client(tempdir, loop):
    client = AsyncClient(
        "https://example.org",
        "ephemeral",
        "DEVICEID",
        tempdir
    )
    yield client

    await client.close()


@pytest.fixture
def aioresponse():
    with aioresponses() as m:
        yield m
