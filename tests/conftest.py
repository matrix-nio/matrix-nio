# -*- coding: utf-8 -*-
import shutil
import sys
import tempfile

import pytest
from olm import Account

import helpers
from nio import Client, ClientConfig, HttpClient
from nio.crypto import Olm, OlmDevice
from nio.store import SqliteMemoryStore

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"

BOB_DEVICE = "@bob:example.org"
BOB_DEVICE_ID = "JLAFKJWSRS"


@pytest.fixture
def tempdir():
    newpath = tempfile.mkdtemp()
    yield newpath
    shutil.rmtree(newpath)


@pytest.fixture
def client(tempdir):
    return Client("ephemeral", "DEVICEID", tempdir)


@pytest.fixture
def client_no_e2e(tempdir):
    config = ClientConfig(encryption_enabled=False)
    return Client("ephemeral", "DEVICEID", tempdir, config)



@pytest.fixture
def olm_machine():
    key_pair = Account().identity_keys

    bob_device = OlmDevice(
            BOB_DEVICE,
            BOB_DEVICE_ID,
            key_pair
        )

    store = SqliteMemoryStore(ALICE_ID, ALICE_DEVICE_ID)
    client = Olm(ALICE_ID, ALICE_DEVICE_ID, store)
    client.device_store.add(bob_device)
    store.save_device_keys(client.device_store)
    return client


@pytest.fixture
def alice_client(tempdir):
    client = Client(ALICE_ID, ALICE_DEVICE_ID, tempdir)
    client.user_id = ALICE_ID
    return client


if sys.version_info >= (3, 5):
    from nio import AsyncClient
    from aioresponses import aioresponses

    @pytest.fixture
    def async_client(tempdir):
        return AsyncClient(
            "https://example.org",
            "ephemeral",
            "DEVICEID",
            tempdir
        )

    @pytest.fixture
    def aioresponse():
        with aioresponses() as m:
            yield m


@pytest.fixture
def http_client(tempdir):
    return HttpClient("example.org", "ephemeral", "DEVICEID", tempdir)


@pytest.fixture
def frame_factory():
    return helpers.FrameFactory()
