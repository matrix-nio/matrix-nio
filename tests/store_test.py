# -*- coding: utf-8 -*-

import os
from collections import defaultdict
from faker import Faker
from faker.providers import BaseProvider
from random import choice
from string import ascii_uppercase

from nio.cryptostore import (
    MatrixStore,
    OlmAccount,
    OlmDevice,
    OutboundSession,
    OutboundGroupSession,
    InboundGroupSession
)

ephermal_dir = os.path.join(os.curdir, "tests/data/encryption")

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"

TEST_ROOM = "!test:example.org"
TEST_FORWARDING_CHAIN = [BOB_CURVE, BOB_ONETIME]

faker = Faker()


def ephermal(func):
    def wrapper(*args, **kwargs):
        try:
            ret = func(*args, **kwargs)
        finally:
            os.remove(os.path.join(
                ephermal_dir,
                "ephermal_DEVICEID.db"
            ))
        return ret
    return wrapper


class Provider(BaseProvider):
    def mx_id(self):
        return "@{}:{}".format(faker.user_name(), faker.hostname())

    def device_id(self):
        return "".join(choice(ascii_uppercase) for i in range(10))

    def olm_key_pair(self):
        return OlmAccount().identity_keys

    def olm_device(self):
        user_id = faker.mx_id()
        device_id = faker.device_id()
        key_pair = faker.olm_key_pair()

        return OlmDevice(
            user_id,
            device_id,
            key_pair["ed25519"],
            key_pair["curve25519"]
        )


faker.add_provider(Provider)


class TestClass(object):
    def _create_test_data(self):
        pass

    @property
    def ephermal_store(self):
        return MatrixStore("ephermal", "DEVICEID", ephermal_dir)

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

    def _create_ephermal_account(self):
        store = self.ephermal_store
        account = OlmAccount()
        store.save_account(account)
        return account

    @ephermal
    def test_store_opening(self):
        store = self.ephermal_store
        account = store.load_account()
        assert not account

    @ephermal
    def test_store_account_saving(self):
        account = self._create_ephermal_account()

        store2 = self.ephermal_store
        loaded_account = store2.load_account()

        assert account.identity_keys == loaded_account.identity_keys

    @ephermal
    def test_store_session(self):
        account = self._create_ephermal_account()
        store = self.ephermal_store

        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)
        store.save_session(BOB_CURVE, session)

        store2 = self.ephermal_store
        session_store = store2.load_sessions()

        loaded_session = session_store.get(BOB_CURVE)

        assert loaded_session
        assert session.id == loaded_session.id

    @ephermal
    def test_store_group_session(self):
        account = self._create_ephermal_account()
        store = self.ephermal_store

        out_group = OutboundGroupSession()
        in_group = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            TEST_FORWARDING_CHAIN
        )
        store.save_inbound_group_session(
            TEST_ROOM,
            account.identity_keys["curve25519"],
            in_group
        )

        store2 = self.ephermal_store
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

    @ephermal
    def test_store_device_keys(self):
        account = self._create_ephermal_account()
        store = self.ephermal_store

        devices = self.example_devices
        assert len(devices) == 11

        store.save_device_keys(devices)

        store2 = self.ephermal_store
        device_store = store2.load_device_keys()

        bob_device = device_store[BOB_ID][BOB_DEVICE]
        assert bob_device
        assert bob_device.user_id == BOB_ID
        assert bob_device.id == BOB_DEVICE
        assert bob_device.ed25519 == BOB_ONETIME
        assert bob_device.curve25519 == BOB_CURVE
        assert not bob_device.deleted
        assert len(device_store.users) == 11

    @ephermal
    def test_two_stores(self):
        try:
            account = self._create_ephermal_account()
            store = self.ephermal_store
            loaded_account = store.load_account()
            assert account.identity_keys == loaded_account.identity_keys

            store2 = MatrixStore("ephermal2", "DEVICEID2", ephermal_dir)
            assert not store2.load_account()

            loaded_account = store.load_account()
            assert account.identity_keys == loaded_account.identity_keys

        finally:
            os.remove(os.path.join(
                ephermal_dir,
                "ephermal2_DEVICEID2.db"
            ))

    @ephermal
    def test_empty_device_keys(self):
        account = self._create_ephermal_account()
        store = self.ephermal_store
        store.save_device_keys(dict())
