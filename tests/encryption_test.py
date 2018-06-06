# -*- coding: utf-8 -*-

import os
import pytest

from olm import Account

from nio.encryption import Olm, OlmDevice, DeviceStore, StoreEntry, OneTimeKey


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

    def test_device_store(self):
        store = DeviceStore(os.path.join(self._test_dir, "ephermal_devices"))
        account = Account()
        device = OlmDevice("example", "DEVICEID", account.identity_keys)
        store.add(device)
        assert device in store
        store.remove(device)
        assert store.check(device) is False
        os.remove(os.path.join(self._test_dir, "ephermal_devices"))

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
