# -*- coding: utf-8 -*-

import os
import pytest

from olm import Account, OutboundSession

from nio.encryption import (FingerprintStore, Olm, OlmDevice, OlmSession,
                            OneTimeKey, SessionStore, DeviceFingerprint,
                            Ed25519Key, DeviceStore, OlmTrustError)


AliceId = "@alice:example.org"
Alice_device = "ALDEVICE"

BobId = "@bob:example.org"
Bob_device = "BOBDEVICE"


class TestClass(object):
    @property
    def _test_dir(self):
        return os.path.join(os.curdir, "tests/data/encryption")

    def test_new_account_creation(self):
        olm = Olm("ephermal", "DEVICEID", self._test_dir)
        assert isinstance(olm.account, Account)
        os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def _load(self, user_id, device_id):
        return Olm(user_id, device_id, self._test_dir)

    def test_account_loading(self):
        olm = self._load("example", "DEVICEID")
        assert isinstance(olm.account, Account)
        assert (olm.account.identity_keys["curve25519"]
                == "Q9k8uSdBnfAdYWyLtBgr7XCz3Nie3nvpSZkwLeeSmXQ")
        assert (olm.account.identity_keys["ed25519"]
                == "LPm6hMOdnbKPsnqp0u84JE6Gprg45Yj3rt+m2bbW0Ag")

    def test_fingerprint_store(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(FingerprintStore, '_save', mocksave)
        store = FingerprintStore(os.path.join(
            self._test_dir,
            "ephermal_devices"
        ))
        account = Account()
        device = OlmDevice("example", "DEVICEID", account.identity_keys)
        fingerprint = DeviceFingerprint.from_olmdevice(device)[0]

        assert fingerprint not in store
        assert store.add(fingerprint)
        assert fingerprint in store
        assert store.remove(fingerprint)
        assert store.check(fingerprint) is False

    def test_fingerprint_store_loading(self):
        store = FingerprintStore(os.path.join(self._test_dir, "known_devices"))
        device = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )

        assert DeviceFingerprint.from_olmdevice(device)[0] in store

    def test_invalid_store_entry_equality(self):
        entry = DeviceFingerprint(
            "example",
            "DEVICEID",
            Ed25519Key("2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA")
        )

        assert entry != 1

    def test_differing_store_entries(self):
        alice = DeviceFingerprint(
            "alice",
            "DEVICEID",
            Ed25519Key("2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA")
        )

        bob = DeviceFingerprint(
            "bob",
            "DEVICEDI",
            Ed25519Key("3MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA")
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
        OneTimeKey(BobId, Bob_device, one_time, "curve25519")
        id_key = bob.identity_keys["curve25519"]
        s = OutboundSession(alice, id_key, one_time)
        return alice, bob, s

    def test_session_store(self):
        alice, bob, s = self._create_session()
        session = OlmSession(BobId, Bob_device, s)
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

        session = OlmSession(BobId, Bob_device, s)
        session2 = OlmSession(BobId, Bob_device, s2)
        store = SessionStore()
        store.add(session)
        store.add(session2)

        if session.session.id < session2.session.id:
            assert session == store.get(BobId, Bob_device)
        else:
            assert session2 == store.get(BobId, Bob_device)

    def test_device_store(self):
        alice = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )

        store = DeviceStore(os.path.join(
            self._test_dir,
            "ephermal_devices"
        ))

        assert store.add(alice)
        assert store.add(alice) is False
        assert alice in store
        os.remove(os.path.join(self._test_dir, "ephermal_devices"))

    def test_device_load(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(FingerprintStore, '_save', mocksave)

        alice = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )
        store = DeviceStore(os.path.join(self._test_dir, "known_devices"))
        assert (DeviceFingerprint.from_olmdevice(alice)[0]
                in store._fingerprint_store)
        assert store.add(alice)
        assert alice in store

    def test_device_invalid(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(FingerprintStore, '_save', mocksave)
        eve = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "3MX2WOCAmE0eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpB"}
        )
        store = DeviceStore(os.path.join(self._test_dir, "known_devices"))
        with pytest.raises(OlmTrustError):
            store.add(eve)

    def test_olm_outbound_session_create(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(FingerprintStore, '_save', mocksave)

        bob = Account()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]

        bob_device = OlmDevice(BobId, Bob_device, bob.identity_keys)

        olm = Olm("ephermal", "DEVICEID", self._test_dir)
        olm.devices.add(bob_device)
        olm.create_session(BobId, Bob_device, one_time)
        assert olm.session_store.get(BobId, Bob_device)
        os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def test_olm_session_load(self):
        olm = self._load("example", "DEVICEID")
        bob_session = olm.session_store.get(BobId, Bob_device)
        assert (bob_session.session.id ==
                "/Pueq/kLxk8o2b+wD6RsQrCgjnV2U6tYN9P+6MBmk6Y")
        assert len(olm.session_store.getall(BobId, Bob_device)) == 2

    def test_olm_inbound_session(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(FingerprintStore, '_save', mocksave)

        # create two new accounts
        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)

        # create olm devices for each others known devices list
        alice_device = OlmDevice(
            AliceId,
            Alice_device,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(BobId, Bob_device, bob.account.identity_keys)

        # add the devices to the device list
        alice.devices.add(bob_device)
        bob.devices.add(alice_device)

        # bob creates one time keys
        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        # Mark the keys as published
        bob.account.mark_keys_as_published()

        # alice creates an outbound olm session with bob
        alice.create_session(BobId, Bob_device, one_time)

        alice_session = alice.session_store.get(BobId, Bob_device)

        payload_dict = {
            "type": "m.room_key",
            "content": {},
            "sender": AliceId,
            "sender_device": Alice_device,
            "keys": {
                "ed25519": alice_device.keys["ed25519"]
            },
            "recipient": BobId,
            "recipient_keys": {
                "ed25519": bob_device.keys["ed25519"]
            }
        }

        # alice encrypts the payload for bob
        message = alice_session.encrypt(Olm._to_json(payload_dict))

        # bob decrypts the message and creates a new inbound session with alice
        bob.decrypt(AliceId, alice_device.keys["curve25519"], message)

        # we check that the session is there
        assert bob.session_store.get(AliceId, Alice_device)

        # remove the databases, the known devices store is handled by
        # monkeypatching
        os.remove(os.path.join(
            self._test_dir,
            "{}_{}.db".format(AliceId, Alice_device)
        ))
        os.remove(os.path.join(
            self._test_dir,
            "{}_{}.db".format(BobId, Bob_device)
        ))
