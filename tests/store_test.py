# -*- coding: utf-8 -*-

import copy
import os
import pdb
from collections import defaultdict
from shutil import copyfile

import pytest

from helpers import ephemeral, ephemeral_dir, faker
from nio.crypto import (InboundGroupSession, OlmAccount, OlmDevice,
                        OutboundGroupSession, OutboundSession,
                        OutgoingKeyRequest)
from nio.exceptions import OlmTrustError
from nio.store import (Ed25519Key, Key, KeyStore, LegacyMatrixStore,
                       MatrixStore, SqliteMemoryStore, SqliteStore)

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"

TEST_ROOM = "!test:example.org"
TEST_ROOM_2 = "!test2:example.org"
TEST_FORWARDING_CHAIN = [BOB_CURVE, BOB_ONETIME]


@pytest.fixture
def matrix_store(tempdir):
    return MatrixStore("ephemeral", "DEVICEID", tempdir)


@pytest.fixture
def store(tempdir):
    store = MatrixStore("ephemeral", "DEVICEID", tempdir)
    account = OlmAccount()
    store.save_account(account)
    return store


@pytest.fixture
def sqlstore(tempdir):
    store = SqliteStore("ephemeral", "DEVICEID", tempdir)
    account = OlmAccount()
    store.save_account(account)
    return store


@pytest.fixture
def sqlmemorystore():
    store = SqliteMemoryStore("ephemeral", "DEVICEID")
    account = OlmAccount()
    store.save_account(account)
    return store


class TestClass(object):
    @property
    def ephemeral_store(self):
        return LegacyMatrixStore(
            "@ephemeral:example.org",
            "DEVICEID",
            ephemeral_dir
        )

    @property
    def example_devices(self):
        devices = defaultdict(dict)

        for _ in range(10):
            device = faker.olm_device()
            devices[device.user_id][device.id] = device

        bob_device = OlmDevice(
            BOB_ID,
            BOB_DEVICE,
            {"ed25519": BOB_ONETIME,
             "curve25519": BOB_CURVE}
        )

        devices[BOB_ID][BOB_DEVICE] = bob_device

        return devices

    def copy_store(self, old_store):
        return MatrixStore(
            old_store.user_id,
            old_store.device_id,
            old_store.store_path
        )

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

            store2 = LegacyMatrixStore("ephemeral2", "DEVICEID2", ephemeral_dir)
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

    @ephemeral
    def test_key_request_saving(self):
        self._create_ephemeral_account()
        store = self.ephemeral_store
        key_requests = store.load_outgoing_key_requests()

        assert not key_requests

        request = OutgoingKeyRequest("ABCDF", "ABCDF", TEST_ROOM, "megolm.v1")
        store.add_outgoing_key_request(request)

        store = self.ephemeral_store
        key_requests = store.load_outgoing_key_requests()
        assert "ABCDF" in key_requests.keys()
        assert request == key_requests["ABCDF"]

    def test_new_store_opening(self, matrix_store):
        account = matrix_store.load_account()
        assert not account

    def test_new_store_account_saving(self, matrix_store):
        account = OlmAccount()
        matrix_store.save_account(account)

        store2 = MatrixStore(
            matrix_store.user_id,
            matrix_store.device_id,
            matrix_store.store_path
        )
        loaded_account = store2.load_account()

        assert account.identity_keys == loaded_account.identity_keys

    def test_new_store_session(self, store):
        account = store.load_account()

        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        store.save_session(BOB_CURVE, session)

        store2 = self.copy_store(store)
        session_store = store2.load_sessions()

        loaded_session = session_store.get(BOB_CURVE)

        assert loaded_session
        assert session.id == loaded_session.id

    def test_new_store_group_session(self, store):
        account = store.load_account()

        out_group = OutboundGroupSession()
        in_group = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            account.identity_keys["curve25519"],
            TEST_ROOM,
            TEST_FORWARDING_CHAIN
        )
        store.save_inbound_group_session(in_group)

        store2 = self.copy_store(store)
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

    def test_new_store_device_keys(self, store):
        account = store.load_account()

        devices = self.example_devices
        assert len(devices) == 11

        store.save_device_keys(devices)

        store2 = self.copy_store(store)
        device_store = store2.load_device_keys()

        # pdb.set_trace()

        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert bob_device
        assert bob_device.user_id == BOB_ID
        assert bob_device.id == BOB_DEVICE
        assert bob_device.ed25519 == BOB_ONETIME
        assert bob_device.curve25519 == BOB_CURVE
        assert not bob_device.deleted
        assert len(device_store.users) == 11

    def test_new_saving_account_twice(self, store):
        account = store.load_account()

        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        store.save_session(BOB_CURVE, session)
        store.save_account(account)

        store2 = self.copy_store(store)
        session_store = store2.load_sessions()

        loaded_session = session_store.get(BOB_CURVE)

        assert loaded_session
        assert session.id == loaded_session.id

    def test_new_encrypted_room_saving(self, store):
        encrypted_rooms = store.load_encrypted_rooms()

        assert not encrypted_rooms

        store.save_encrypted_rooms([TEST_ROOM])

        store2 = self.copy_store(store)
        encrypted_rooms = store2.load_encrypted_rooms()
        assert TEST_ROOM in encrypted_rooms

    def test_new_encrypted_room_delete(self, store):
        encrypted_rooms = store.load_encrypted_rooms()

        assert not encrypted_rooms

        store.save_encrypted_rooms([TEST_ROOM, TEST_ROOM_2])

        store2 = self.copy_store(store)
        encrypted_rooms = store2.load_encrypted_rooms()
        assert TEST_ROOM in encrypted_rooms
        assert TEST_ROOM_2 in encrypted_rooms

        store.delete_encrypted_room(TEST_ROOM_2)
        store3 = self.copy_store(store2)
        encrypted_rooms = store3.load_encrypted_rooms()
        assert TEST_ROOM in encrypted_rooms
        assert TEST_ROOM_2 not in encrypted_rooms

    def test_new_key_request_saving(self, store):
        key_requests = store.load_outgoing_key_requests()

        assert not key_requests

        request = OutgoingKeyRequest("ABCDF", "ABCDF", TEST_ROOM, "megolm.v1")
        store.add_outgoing_key_request(request)

        store2 = self.copy_store(store)
        key_requests = store2.load_outgoing_key_requests()
        assert "ABCDF" in key_requests.keys()
        assert request == key_requests["ABCDF"]

    def test_db_upgrade(self, tempdir):
        user = "ephemeral"
        device_id = "DEVICE_ID"
        user2 = "alice"
        device_id2 = "ALICE_ID"

        store = LegacyMatrixStore(user, device_id, tempdir,
                                  database_name="test.db")
        account = OlmAccount()
        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        out_group = OutboundGroupSession()
        in_group = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            account.identity_keys["curve25519"],
            TEST_ROOM,
            TEST_FORWARDING_CHAIN
        )
        devices = self.example_devices
        assert len(devices) == 11

        store.save_account(account)
        store.save_session(BOB_CURVE, session)
        store.save_inbound_group_session(in_group)
        store.save_device_keys(devices)

        store2 = LegacyMatrixStore(user2, device_id2, tempdir,
                                   database_name="test.db")
        account2 = OlmAccount()
        store2.save_account(account2)
        del store

        store = MatrixStore(user, device_id, tempdir, database_name="test.db")
        loaded_account = store.load_account()

        assert account.identity_keys == loaded_account.identity_keys
        session_store = store.load_sessions()
        loaded_session = session_store.get(BOB_CURVE)
        session_store = store.load_inbound_group_sessions()

        assert loaded_session
        assert session.id == loaded_session.id

        loaded_session = session_store.get(
            TEST_ROOM,
            account.identity_keys["curve25519"],
            in_group.id
        )
        device_store = store.load_device_keys()

        # pdb.set_trace()

        assert loaded_session
        assert in_group.id == loaded_session.id
        assert (sorted(loaded_session.forwarding_chain) ==
                sorted(TEST_FORWARDING_CHAIN))
        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert bob_device
        assert bob_device.user_id == BOB_ID
        assert bob_device.id == BOB_DEVICE
        assert bob_device.ed25519 == BOB_ONETIME
        assert bob_device.curve25519 == BOB_CURVE
        assert not bob_device.deleted
        assert len(device_store.users) == 11

    def test_real_db_upgrade(self, tempdir):
        path = os.path.abspath("tests/data/weechat_test.db")
        copyfile(path, os.path.join(tempdir, "weechat_test.db"))
        print(path)
        store = MatrixStore(
            "@pjtest:termina.org.uk",
            "LHNALLSCNA",
            tempdir,
            "DEFAULT_KEY",
            database_name="weechat_test.db"
        )
        store.save_encrypted_rooms([TEST_ROOM])

        account = store.load_account()
        encrypted_rooms = store.load_encrypted_rooms()

        assert TEST_ROOM in encrypted_rooms
        assert account.identity_keys == {
            "curve25519": "si7g1tFp4uhI+vzesW/zxss6Au/7Ufp+AKi7EGO+PHU",
            "ed25519": "JO4Q52p01yLoC9GuIYrded+heHBtI0ZxhZssvZ0xOt8"
        }

    def test_store_versioning(self, store):
        version = store._get_store_version()

        assert version == 2

    def test_sqlitestore_verification(self, sqlstore):
        devices = self.example_devices
        bob_device = devices[BOB_ID][BOB_DEVICE]

        sqlstore.save_device_keys(devices)

        assert not sqlstore.is_device_verified(bob_device)
        assert sqlstore.verify_device(bob_device)
        assert sqlstore.is_device_verified(bob_device)
        assert not sqlstore.verify_device(bob_device)
        assert sqlstore.is_device_verified(bob_device)
        assert sqlstore.unverify_device(bob_device)
        assert not sqlstore.is_device_verified(bob_device)
        assert not sqlstore.unverify_device(bob_device)

    def test_sqlitestore_blacklisting(self, sqlstore):
        devices = self.example_devices
        bob_device = devices[BOB_ID][BOB_DEVICE]

        sqlstore.save_device_keys(devices)

        assert not sqlstore.is_device_blacklisted(bob_device)
        assert sqlstore.blacklist_device(bob_device)
        assert sqlstore.is_device_blacklisted(bob_device)
        assert not sqlstore.is_device_verified(bob_device)
        assert not sqlstore.blacklist_device(bob_device)
        assert sqlstore.unblacklist_device(bob_device)
        assert not sqlstore.is_device_blacklisted(bob_device)
        assert not sqlstore.is_device_verified(bob_device)
        assert not sqlstore.unblacklist_device(bob_device)
        assert sqlstore.blacklist_device(bob_device)
        assert sqlstore.is_device_blacklisted(bob_device)
        assert sqlstore.verify_device(bob_device)
        assert not sqlstore.is_device_blacklisted(bob_device)
        assert sqlstore.is_device_verified(bob_device)

    def test_sqlitememorystore(self, sqlmemorystore):
        devices = self.example_devices
        bob_device = devices[BOB_ID][BOB_DEVICE]
        sqlmemorystore.save_device_keys(devices)

        assert not sqlmemorystore.is_device_verified(bob_device)
        assert sqlmemorystore.verify_device(bob_device)
        assert sqlmemorystore.is_device_verified(bob_device)

    def test_device_deletion(self, store):
        account = store.load_account()

        devices = self.example_devices
        assert len(devices) == 11

        store.save_device_keys(devices)
        device_store = store.load_device_keys()
        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert not bob_device.deleted
        bob_device.deleted = True
        store.save_device_keys(device_store)
        device_store = store.load_device_keys()
        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert bob_device.deleted

    def test_deleting_trusted_device(self, sqlstore):
        devices = self.example_devices
        sqlstore.save_device_keys(devices)

        device_store = sqlstore.load_device_keys()
        bob_device = device_store[BOB_ID][BOB_DEVICE]
        sqlstore.verify_device(bob_device)

        bob_device.deleted = True
        sqlstore.save_device_keys(device_store)
        sqlstore.save_device_keys(devices)
