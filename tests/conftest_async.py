import pytest

from nio import AsyncClient, LoginResponse
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
async def async_client_pair(tempdir, loop):
    ALICE_ID = "@alice:example.org"
    ALICE_DEVICE = "JLAFKJWSCS"

    BOB_ID = "@bob:example.org"
    BOB_DEVICE = "ASDFOEAK"

    alice = AsyncClient("https://example.org", ALICE_ID, ALICE_DEVICE, tempdir)
    bob = AsyncClient("https://example.org", BOB_ID, BOB_DEVICE, tempdir)

    await alice.receive_response(LoginResponse(ALICE_ID, ALICE_DEVICE, "alice_1234"))
    await bob.receive_response(LoginResponse(BOB_ID, BOB_DEVICE, "bob_1234"))

    yield (alice, bob)

    await alice.close()
    await bob.close()


@pytest.fixture
def aioresponse():
    with aioresponses() as m:
        yield m
