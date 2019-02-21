# -*- coding: utf-8 -*-

import os
import copy
import pytest
from collections import defaultdict
from helpers import faker, ephemeral, ephemeral_dir

from nio.store import MatrixStore, Key, Ed25519Key, KeyStore
from nio.exceptions import OlmTrustError

from nio.crypto import (
    OlmAccount,
    OlmDevice,
    OutboundSession,
    OutboundGroupSession,
    InboundGroupSession
)

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"

TEST_ROOM = "!test:example.org"
TEST_FORWARDING_CHAIN = [BOB_CURVE, BOB_ONETIME]


class TestClass(object):
    @property
    def ephemeral_store(self):
        return MatrixStore("@ephemeral:example.org", "DEVICEID", ephemeral_dir)

    @property
    def example_devices(self):
        devices = defaultdict(dict)

        for _ in range(10):
            device = faker.olm_device()
            devices[device.user_id][device.id] = device

        bob_device = OlmDevice(
            BOB_ID,
            BOB_DEVICE,
            BOB_ONETIME,
            BOB_CURVE
        )

        devices[BOB_ID][BOB_DEVICE] = bob_device

        return devices

    def _create_ephemeral_account(self):
        store = self.ephemeral_store
        account = OlmAccount()
        store.save_account(account)
        return account

    def test_key(self):
        user_id = faker.mx_id()
        device_id = faker.device_id()
        fp_key = faker.olm_key_pair()["ed25519"]
        key = Ed25519Key(user_id, device_id, fp_key)

        assert (
            key.to_line() == "{} {} matrix-ed25519 {}\n".format(
                user_id,
                device_id,
                fp_key
            )
        )

        loaded_key = Key.from_line(key.to_line())
        assert isinstance(loaded_key, Ed25519Key)

        assert key.user_id == loaded_key.user_id
        assert key.device_id == loaded_key.device_id
        assert key.key == loaded_key.key
        assert key == loaded_key

    def test_key_store(self, tempdir):
        store_path = os.path.join(tempdir, "test_store")
        store = KeyStore(os.path.join(tempdir, "test_store"))
        assert repr(store) == "KeyStore object, file: {}".format(store_path)

        key = faker.ed25519_key()

        store.add(key)

        assert key == store.get_key(key.user_id, key.device_id)

    def test_key_store_add_invalid(self, tempdir):
        store_path = os.path.join(tempdir, "test_store")
        store = KeyStore(os.path.join(tempdir, "test_store"))

        key = faker.ed25519_key()
        store.add(key)

        fake_key = copy.copy(key)
        fake_key.key = "FAKE_KEY"

        with pytest.raises(OlmTrustError):
            store.add(fake_key)

    def test_key_store_check_invalid(self, tempdir):
        store_path = os.path.join(tempdir, "test_store")
        store = KeyStore(os.path.join(tempdir, "test_store"))

        key = faker.ed25519_key()
        store.add(key)

        fake_key = copy.copy(key)
        fake_key.key = "FAKE_KEY"

        assert fake_key not in store
        assert key in store

    @ephemeral
    def test_store_opening(self):
        store = self.ephemeral_store
        account = store.load_account()
        assert not account

    @ephemeral
    def test_store_account_saving(self):
        account = self._create_ephemeral_account()

        store2 = self.ephemeral_store
        loaded_account = store2.load_account()

        assert account.identity_keys == loaded_account.identity_keys

    @ephemeral
    def test_store_session(self):
        account = self._create_ephemeral_account()
        store = self.ephemeral_store

        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        store.save_session(BOB_CURVE, session)

        store2 = self.ephemeral_store
        session_store = store2.load_sessions()

        loaded_session = session_store.get(BOB_CURVE)

        assert loaded_session
        assert session.id == loaded_session.id

    @ephemeral
    def test_store_group_session(self):
        account = self._create_ephemeral_account()
        store = self.ephemeral_store

        out_group = OutboundGroupSession()
        in_group = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            account.identity_keys["curve25519"],
            TEST_ROOM,
            TEST_FORWARDING_CHAIN
        )
        store.save_inbound_group_session(in_group)

        store2 = self.ephemeral_store
        session_store = store2.load_inbound_group_sessions()

        loaded_session = session_store.get(
            TEST_ROOM,
            account.identity_keys["curve25519"],
            in_group.id
        )

        assert loaded_session
        assert in_group.id == loaded_session.id
        assert (sorted(loaded_session.forwarding_chain) ==
                sorted(TEST_FORWARDING_CHAIN))

    @ephemeral
    def test_store_device_keys(self):
        account = self._create_ephemeral_account()
        store = self.ephemeral_store

        devices = self.example_devices
        assert len(devices) == 11

        store.save_device_keys(devices)

        store2 = self.ephemeral_store
        device_store = store2.load_device_keys()

        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert bob_device
        assert bob_device.user_id == BOB_ID
        assert bob_device.id == BOB_DEVICE
        assert bob_device.ed25519 == BOB_ONETIME
        assert bob_device.curve25519 == BOB_CURVE
        assert not bob_device.deleted
        assert len(device_store.users) == 11

    @ephemeral
    def test_two_stores(self):
        try:
            account = self._create_ephemeral_account()
            store = self.ephemeral_store
            loaded_account = store.load_account()
            assert account.identity_keys == loaded_account.identity_keys

            store2 = MatrixStore("ephemeral2", "DEVICEID2", ephemeral_dir)
            assert not store2.load_account()

            loaded_account = store.load_account()
            assert account.identity_keys == loaded_account.identity_keys

        finally:
            os.remove(os.path.join(
                ephemeral_dir,
                "ephemeral2_DEVICEID2.db"
            ))

    @ephemeral
    def test_empty_device_keys(self):
        account = self._create_ephemeral_account()
        store = self.ephemeral_store
        store.save_device_keys(dict())

    @ephemeral
    def test_saving_account_twice(self):
        account = self._create_ephemeral_account()
        store = self.ephemeral_store

        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        store.save_session(BOB_CURVE, session)
        store.save_account(account)

        store2 = self.ephemeral_store
        session_store = store2.load_sessions()

        loaded_session = session_store.get(BOB_CURVE)

        assert loaded_session
        assert session.id == loaded_session.id

    @ephemeral
    def test_encrypted_room_saving(self):
        self._create_ephemeral_account()
        store = self.ephemeral_store
        encrypted_rooms = store.load_encrypted_rooms()

        assert not encrypted_rooms

        store.save_encrypted_rooms([TEST_ROOM])

        store = self.ephemeral_store
        encrypted_rooms = store.load_encrypted_rooms()
        assert TEST_ROOM in encrypted_rooms
