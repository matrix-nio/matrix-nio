# -*- coding: utf-8 -*-

import os
import pytest
import json

from olm import (
    Account,
    OutboundSession,
    OutboundGroupSession,
    OlmPreKeyMessage,
    OlmMessage
)

from nio.encryption import (KeyStore, Olm,
                            SessionStore, Ed25519Key, DeviceStore, Key,
                            OlmTrustError)
from nio.cryptostore import OlmDevice
from nio.responses import KeysQueryResponse


AliceId = "@alice:example.org"
Alice_device = "ALDEVICE"

BobId = "@bob:example.org"
Bob_device = "BOBDEVICE"


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

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
                == "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM")
        assert (olm.account.identity_keys["ed25519"]
                == "FEfrmWlasr4tcMtbNX/BU5lbdjmpt3ptg8ApTD8YAh4")

    def test_fingerprint_store(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)
        store = KeyStore(os.path.join(
            self._test_dir,
            "ephermal_devices"
        ))
        account = Account()
        device = OlmDevice(
            "example",
            "DEVICEID",
            account.identity_keys["ed25519"],
            account.identity_keys["curve25519"],
        )
        key = Key.from_olmdevice(device)

        assert key not in store
        assert store.add(key)
        assert key in store
        assert store.remove(key)
        assert store.check(key) is False

    def test_fingerprint_store_loading(self):
        store = KeyStore(os.path.join(self._test_dir, "known_devices"))
        key = Ed25519Key(
            "example",
            "DEVICEID",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        assert key in store

    def test_invalid_store_entry_equality(self):
        entry = Ed25519Key(
            "example",
            "DEVICEID",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        assert entry != 1

    def test_differing_store_entries(self):
        alice = Ed25519Key(
            "alice",
            "DEVICEID",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        bob = Ed25519Key(
            "bob",
            "DEVICEDI",
            "3MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        assert alice != bob

    def _create_session(self):
        alice = Account()
        bob = Account()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]
        id_key = bob.identity_keys["curve25519"]
        s = OutboundSession(alice, id_key, one_time)
        return alice, bob, s

    def test_session_store(self):
        alice, bob, s = self._create_session()
        store = SessionStore()
        store.add(bob.identity_keys["curve25519"], s)
        assert s in store

    def test_session_store_sort(self):
        alice, bob, s = self._create_session()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]
        curve_key = bob.identity_keys["curve25519"]
        s2 = OutboundSession(alice, curve_key, one_time)

        store = SessionStore()
        store.add(curve_key, s)
        store.add(curve_key, s2)

        if s.id < s2.id:
            assert s == store.get(curve_key)
        else:
            assert s2 == store.get(curve_key)

    def test_device_store(self):
        alice = OlmDevice(
            "example",
            "DEVICEID",
            "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA",
            "3MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"
        )

        store = DeviceStore()

        assert store.add(alice)
        assert store.add(alice) is False
        assert alice in store

    def test_olm_outbound_session_create(self):
        bob = Account()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]

        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.identity_keys["ed25519"],
            bob.identity_keys["curve25519"]
        )

        olm = Olm("ephermal", "DEVICEID", self._test_dir)
        olm.device_store[bob_device.user_id][bob_device.id] = bob_device
        olm.create_session(one_time, bob_device.curve25519)
        assert isinstance(
            olm.session_store.get(bob.identity_keys["curve25519"]),
            OutboundSession
        )
        os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def test_olm_session_load(self):
        olm = self._load("example", "DEVICEID")

        bob_session = olm.session_store.get(
            "+Qs131S/odNdWG6VJ8hiy9YZW0us24wnsDjYQbaxLk4"
        )
        assert bob_session
        assert (bob_session.id
                == "EeEiqT9LjCtECaN7WTqcBQ7D5Dwm4+/L9Uxr1IyPAts")

    def test_olm_group_session_store(self):
        try:
            olm = Olm("ephermal", "DEVICEID", self._test_dir)
            bob_account = Account()
            outbound_session = OutboundGroupSession()
            olm.create_group_session(
                bob_account.identity_keys["curve25519"],
                bob_account.identity_keys["ed25519"],
                "!test_room",
                outbound_session.id,
                outbound_session.session_key)

            del olm

            olm = self._load("ephermal", "DEVICEID")

            bob_session = olm.inbound_group_store.get(
                "!test_room",
                bob_account.identity_keys["curve25519"],
                outbound_session.id
            )

            assert bob_session
            assert (bob_session.id
                    == outbound_session.id)

        finally:
            os.remove(os.path.join(self._test_dir, "ephermal_DEVICEID.db"))

    def test_keys_query(self):
        try:
            olm = Olm("ephermal", "DEVICEID", self._test_dir)
            parsed_dict = TestClass._load_response(
                "tests/data/keys_query.json")
            response = KeysQueryResponse.from_dict(parsed_dict)

            assert isinstance(response, KeysQueryResponse)

            olm.handle_response(response)
            device = olm.device_store["@alice:example.org"]["JLAFKJWSCS"]
            assert (
                device.ed25519 == "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM"
            )

            del olm

            olm = Olm("ephermal", "DEVICEID", self._test_dir)
            device = olm.device_store["@alice:example.org"]["JLAFKJWSCS"]
            assert (
                device.ed25519 == "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM"
            )
        finally:
            os.remove(os.path.join(
                self._test_dir, "ephermal_DEVICEID.db"))

    def test_olm_inbound_session(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)

        # create two new accounts
        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)

        # create olm devices for each others known devices list
        alice_device = OlmDevice(
            AliceId,
            Alice_device,
            alice.account.identity_keys["ed25519"],
            alice.account.identity_keys["curve25519"],
        )
        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.account.identity_keys["ed25519"],
            bob.account.identity_keys["curve25519"],
        )

        # add the devices to the device list
        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        # bob creates one time keys
        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        # Mark the keys as published
        bob.account.mark_keys_as_published()

        # alice creates an outbound olm session with bob
        alice.create_session(one_time, bob_device.curve25519)

        # alice creates an group session
        alice.create_outbound_group_session("!test:example.org")
        group_session = alice.outbound_group_sessions["!test:example.org"]

        # alice shares the group session with bob
        with pytest.raises(OlmTrustError):
            to_device = alice.share_group_session("!test:example.org", [BobId])

        alice.verify_device(bob_device)
        to_device = alice.share_group_session("!test:example.org", [BobId])
        ciphertext = to_device["messages"][BobId][bob_device.id]["ciphertext"]
        bob_ciphertext = ciphertext[bob_device.curve25519]

        message = (OlmPreKeyMessage(bob_ciphertext["body"])
                   if bob_ciphertext["type"] == 0
                   else OlmMessage(bob_ciphertext["body"]))

        # bob decrypts the message and creates a new inbound session with alice
        try:
            # pdb.set_trace()
            bob.decrypt(AliceId, alice_device.curve25519, message)

            # we check that the session is there
            assert bob.session_store.get(alice_device.curve25519)
            # we check that the group session is there
            assert bob.inbound_group_store.get(
                "!test:example.org",
                alice_device.curve25519,
                group_session.id,
            )

        finally:
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
