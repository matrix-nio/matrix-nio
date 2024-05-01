import shutil
from pathlib import Path

import helpers
import pytest
from conftest_async import (  # noqa: F401
    aioresponse,
    async_client,
    async_client_pair,
    async_client_pair_same_user,
    unauthed_async_client,
)
from olm import Account

from nio import Client, ClientConfig, HttpClient
from nio.crypto import Olm, OlmDevice
from nio.store import SqliteMemoryStore

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"

BOB_DEVICE = "@bob:example.org"
BOB_DEVICE_ID = "JLAFKJWSRS"


_ephemeral_dir = Path.cwd() / "tests/data/encryption"


@pytest.fixture
def ephemeral_dir(tmp_path: Path):
    shutil.copytree(_ephemeral_dir, tmp_path, dirs_exist_ok=True)
    return tmp_path


@pytest.fixture
def client(tmp_path):
    return Client("ephemeral", "DEVICEID", tmp_path)


@pytest.fixture
def client_no_e2e(tmp_path):
    config = ClientConfig(encryption_enabled=False)
    return Client("ephemeral", "DEVICEID", tmp_path, config)


@pytest.fixture
def olm_machine():
    key_pair = Account().identity_keys

    bob_device = OlmDevice(BOB_DEVICE, BOB_DEVICE_ID, key_pair)

    store = SqliteMemoryStore(ALICE_ID, ALICE_DEVICE_ID)
    client = Olm(ALICE_ID, ALICE_DEVICE_ID, store)
    client.device_store.add(bob_device)
    store.save_device_keys(client.device_store)
    return client


@pytest.fixture
def alice_client(tmp_path):
    client = Client(ALICE_ID, ALICE_DEVICE_ID, tmp_path)
    client.user_id = ALICE_ID
    return client


@pytest.fixture
def http_client(tmp_path):
    return HttpClient("example.org", "ephemeral", "DEVICEID", tmp_path)


@pytest.fixture
def frame_factory():
    return helpers.FrameFactory()
