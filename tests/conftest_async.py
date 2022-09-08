import pytest
import pytest_asyncio
from aioresponses import aioresponses

from nio import AsyncClient, AsyncClientConfig, LoginResponse


@pytest_asyncio.fixture
async def async_client(tempdir):
    client = AsyncClient(
        "https://example.org",
        "ephemeral",
        "DEVICEID",
        tempdir,
        config=AsyncClientConfig(max_timeouts=3),
    )
    yield client

    await client.close()


@pytest_asyncio.fixture
async def async_client_pair(tempdir):
    ALICE_ID = "@alice:example.org"
    ALICE_DEVICE = "JLAFKJWSCS"

    BOB_ID = "@bob:example.org"
    BOB_DEVICE = "ASDFOEAK"

    config = AsyncClientConfig(max_timeouts=3)
    alice = AsyncClient(
        "https://example.org",
        ALICE_ID,
        ALICE_DEVICE,
        tempdir,
        config=config,
    )
    bob = AsyncClient(
        "https://example.org",
        BOB_ID,
        BOB_DEVICE,
        tempdir,
        config=config,
    )

    await alice.receive_response(LoginResponse(ALICE_ID, ALICE_DEVICE, "alice_1234"))
    await bob.receive_response(LoginResponse(BOB_ID, BOB_DEVICE, "bob_1234"))

    yield (alice, bob)

    await alice.close()
    await bob.close()


@pytest_asyncio.fixture
def aioresponse():
    with aioresponses() as m:
        yield m
