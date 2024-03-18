import pytest_asyncio
from aioresponses import aioresponses

from nio import AsyncClient, AsyncClientConfig, LoginResponse
from nio.crypto import OlmDevice


@pytest_asyncio.fixture
async def async_client(tempdir) -> AsyncClient:
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
async def async_client_pair_same_user(tempdir):
    ALICE_ID = "@alice:example.org"
    FIRST_DEVICE = "JLAFKJWSCS"

    SECOND_DEVICE = "ASDFOEAK"

    config = AsyncClientConfig(max_timeouts=3)
    alice = AsyncClient(
        "https://example.org",
        ALICE_ID,
        FIRST_DEVICE,
        tempdir,
        config=config,
    )
    bob = AsyncClient(
        "https://example.org",
        ALICE_ID,
        SECOND_DEVICE,
        tempdir,
        config=config,
    )

    await alice.receive_response(LoginResponse(ALICE_ID, FIRST_DEVICE, "alice_1234"))
    await bob.receive_response(LoginResponse(ALICE_ID, SECOND_DEVICE, "bob_1234"))
    alice_device = OlmDevice(
        alice.user_id, alice.device_id, alice.olm.account.identity_keys
    )
    bob_device = OlmDevice(bob.user_id, bob.device_id, bob.olm.account.identity_keys)

    alice.olm.device_store.add(bob_device)
    bob.olm.device_store.add(alice_device)
    alice.verify_device(bob_device)
    bob.verify_device(alice_device)

    yield (alice, bob)

    await alice.close()
    await bob.close()


@pytest_asyncio.fixture
def aioresponse():
    with aioresponses() as m:
        yield m
