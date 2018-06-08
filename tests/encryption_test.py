# -*- coding: utf-8 -*-

import os

import pytest
from olm import Account, OutboundSession

from nio.encryption import (DeviceStore, Olm, OlmDevice, OlmSession,
                            OneTimeKey, SessionStore, StoreEntry)


class TestClass(object):
    @property
    def _test_dir(self):
        return os.path.join(os.curdir, "tests/data/encryption")

    def test_new_account_creation(self):
        olm = Olm("ephermal", "DEVICEID", self._test_dir)
        assert isinstance(olm.account, Account)
        os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def test_account_loading(self):
        olm = Olm("example", "DEVICEID", self._test_dir)
        assert isinstance(olm.account, Account)
        assert (olm.account.identity_keys["curve25519"]
                == "Q9k8uSdBnfAdYWyLtBgr7XCz3Nie3nvpSZkwLeeSmXQ")

    def test_device_store(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(DeviceStore, '_save', mocksave)
        store = DeviceStore(os.path.join(self._test_dir, "ephermal_devices"))
        account = Account()
        device = OlmDevice("example", "DEVICEID", account.identity_keys)
        assert device not in store
        store.add(device)
        assert device in store
        store.remove(device)
        assert store.check(device) is False

    def test_device_store_loading(self):
        store = DeviceStore(os.path.join(self._test_dir, "known_devices"))
        device = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )

        assert device in store

    def test_invalid_store_entry_equality(self):
        entry = StoreEntry(
            "example",
            "DEVICEID",
            "ed25519",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        assert entry != 1

    def test_differing_store_entries(self):
        alice = StoreEntry(
            "alice",
            "DEVICEID",
            "ed25519",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        bob = StoreEntry(
            "bob",
            "DEVICEDI",
            "ed25519",
            "3MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        assert alice != bob

    def test_str_device(self):
        device = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )
        device_str = ("example DEVICEID " "{'ed25519': "
                      "'2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA'}")
        assert str(device) == device_str

    def test_invalid_device_equality(self):
        device = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )
        assert device != 1

    def test_uknown_key_equality(self):
        alice = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )
        bob = OlmDevice(
            "example",
            "DEVICEID",
            {"rsa": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )
        assert alice != bob

    def test_one_time_key_creation(self):
        key = OneTimeKey(
            "example",
            "DEVICEID",
            "ubIIABa6OJqXKBgjTBweu9byDQ6bRcv+1Ha5zZ8Sv3M",
            "curve25519"
        )
        assert isinstance(key, OneTimeKey)

    def _create_session(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]
        OneTimeKey("@bob:example.org", "BOBDEVICE", one_time, "curve25519")
        id_key = bob.identity_keys["curve25519"]
        s = OutboundSession(alice, id_key, one_time)
        return alice, bob, s

    def test_session_store(self):
        alice, bob, s = self._create_session()
        session = OlmSession("@bob:example.org", "BOBDEVICE", s)
        store = SessionStore()
        store.add(session)
        assert store.check(session)
        assert session in store

    def test_session_store_sort(self):
        alice, bob, s = self._create_session()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]
        id_key = bob.identity_keys["curve25519"]
        s2 = OutboundSession(alice, id_key, one_time)

        session = OlmSession("@bob:example.org", "BOBDEVICE", s)
        session2 = OlmSession("@bob:example.org", "BOBDEVICE", s2)
        store = SessionStore()
        store.add(session)
        store.add(session2)

        if session.session.id < session2.session.id:
            assert session == store.get("@bob:example.org", "BOBDEVICE")
        else:
            assert session2 == store.get("@bob:example.org", "BOBDEVICE")
