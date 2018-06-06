# -*- coding: utf-8 -*-

import os

from olm import Account

from nio.encryption import Olm, OlmDevice, DeviceStore


class TestClass(object):
    @property
    def _test_dir(self):
        return os.path.join(os.curdir, "tests/data/encryption")

    def test_new_account_creation(self):
        olm = Olm("ephermal", "DEVICEID", self._test_dir)
        assert isinstance(olm.account, Account)
        os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def test_new_account_loading(self):
        olm = Olm("example", "DEVICEID", self._test_dir)
        assert isinstance(olm.account, Account)
        assert (olm.account.identity_keys["curve25519"]
                == "Q9k8uSdBnfAdYWyLtBgr7XCz3Nie3nvpSZkwLeeSmXQ")

    def test_device_store(self):
        store = DeviceStore(os.path.join(self._test_dir, "known_devices"))
        account = Account()
        device = OlmDevice("example", "DEVICEID", account.identity_keys)
        store.add(device)
        assert device in store
        store.remove(device)
        assert store.check(device) is False
        os.remove(os.path.join(self._test_dir, "known_devices"))
