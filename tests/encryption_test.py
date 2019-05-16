# -*- coding: utf-8 -*-

import copy
import json
import os

import pytest
from olm import Account, OlmMessage, OlmPreKeyMessage, OutboundGroupSession

from nio.crypto import (DeviceStore, GroupSessionStore, InboundGroupSession,
                        Olm, OlmDevice, OutboundSession, OutgoingKeyRequest,
                        SessionStore)
from nio.events import (ForwardedRoomKeyEvent, MegolmEvent, OlmEvent,
                        RoomKeyEvent, RoomMessageText, UnknownBadEvent)
from nio.exceptions import EncryptionError, GroupEncryptionError, OlmTrustError
from nio.responses import (KeysClaimResponse, KeysQueryResponse,
                           KeysUploadResponse)
from nio.store import DefaultStore, Ed25519Key, Key, KeyStore

AliceId = "@alice:example.org"
Alice_device = "ALDEVICE"

BobId = "@bob:example.org"
Bob_device = "BOBDEVICE"

MaloryId = "@malory:example.org"
Malory_device = "MALORYDEVICE"

PICKLE_KEY = "DEFAULT_KEY"
TEST_ROOM = "!test_room"

ephemeral_dir = os.path.join(os.curdir, "tests/data/encryption")

def ephemeral(func):
    def wrapper(*args, **kwargs):
        try:
            ret = func(*args, **kwargs)
        finally:
            os.remove(os.path.join(
                ephemeral_dir,
                "ephemeral_DEVICEID.db"
            ))
        return ret
    return wrapper

class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def _get_store(self, user_id, device_id, pickle_key=""):
        return DefaultStore(user_id, device_id, ephemeral_dir, pickle_key)

    @property
    def ephemeral_olm(self):
        user_id = "ephemeral"
        device_id = "DEVICEID"
        return Olm(user_id, device_id, self._get_store(user_id, device_id))

    @ephemeral
    def test_new_account_creation(self):
        olm = self.ephemeral_olm
        assert isinstance(olm.account, Account)

    def _load(self, user_id, device_id, pickle_key=""):
        return Olm(
            user_id,
            device_id,
            self._get_store(user_id, device_id, pickle_key)
        )

    def test_account_loading(self):
        olm = self._load("example", "DEVICEID", PICKLE_KEY)
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
            ephemeral_dir,
            "ephemeral_devices"
        ))
        account = Account()
        device = OlmDevice(
            "example",
            "DEVICEID",
            account.identity_keys
        )
        key = Key.from_olmdevice(device)

        assert key not in store
        assert store.add(key)
        assert key in store
        assert store.remove(key)
        assert store.check(key) is False

    def test_fingerprint_store_loading(self):
        store = KeyStore(os.path.join(ephemeral_dir, "known_devices"))
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
            {"edd25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA",
             "curve25519": "3MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA"}
        )

        store = DeviceStore()

        assert store.add(alice)
        assert store.add(alice) is False
        assert alice in store

    @ephemeral
    def test_olm_outbound_session_create(self):
        bob = Account()
        bob.generate_one_time_keys(1)
        one_time = list(bob.one_time_keys["curve25519"].values())[0]

        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.identity_keys
        )

        olm = self.ephemeral_olm
        olm.device_store[bob_device.user_id][bob_device.id] = bob_device
        olm.create_session(one_time, bob_device.curve25519)
        assert isinstance(
            olm.session_store.get(bob.identity_keys["curve25519"]),
            OutboundSession
        )

    def test_olm_session_load(self):
        olm = self._load("example", "DEVICEID", PICKLE_KEY)

        bob_session = olm.session_store.get(
            "+Qs131S/odNdWG6VJ8hiy9YZW0us24wnsDjYQbaxLk4"
        )
        assert bob_session
        assert (bob_session.id
                == "EeEiqT9LjCtECaN7WTqcBQ7D5Dwm4+/L9Uxr1IyPAts")

    @ephemeral
    def test_olm_group_session_store(self):
        olm = self.ephemeral_olm
        bob_account = Account()
        outbound_session = OutboundGroupSession()
        olm.create_group_session(
            bob_account.identity_keys["curve25519"],
            bob_account.identity_keys["ed25519"],
            "!test_room",
            outbound_session.id,
            outbound_session.session_key)

        del olm

        olm = self.ephemeral_olm

        bob_session = olm.inbound_group_store.get(
            "!test_room",
            bob_account.identity_keys["curve25519"],
            outbound_session.id
        )

        assert bob_session
        assert (bob_session.id
                == outbound_session.id)

    @ephemeral
    def test_keys_query(self):
        olm = self.ephemeral_olm
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

        olm = self.ephemeral_olm
        device = olm.device_store["@alice:example.org"]["JLAFKJWSCS"]
        assert (
            device.ed25519 == "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM"
        )

    @ephemeral
    def test_same_query_response_twice(self):
        olm = self.ephemeral_olm
        parsed_dict = TestClass._load_response(
            "tests/data/keys_query.json")
        response = KeysQueryResponse.from_dict(parsed_dict)
        olm.handle_response(response)
        assert response.changed

        # TODO check out why this fails under python2 if we remove the copy()
        # call.
        response2 = copy.copy(response)
        olm.handle_response(response)
        assert response2.changed


    def test_olm_inbound_session(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)

        # create three new accounts
        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)
        malory = self._load(BobId, Bob_device)

        # create olm devices for each others known devices list
        alice_device = OlmDevice(
            AliceId,
            Alice_device,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.account.identity_keys
        )

        malory_device = OlmDevice(
            MaloryId,
            Malory_device,
            malory.account.identity_keys
        )

        # add the devices to the device list
        alice.device_store.add(bob_device)
        alice.device_store.add(malory_device)
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

        # alice shares the group session with bob, but bob isn't verified
        with pytest.raises(OlmTrustError):
            sharing_with, to_device = alice.share_group_session(
                "!test:example.org",
                [BobId]
            )

        alice.verify_device(bob_device)

        # alice shares the group session with bob and malory, but malory isn't
        # blocked
        with pytest.raises(OlmTrustError):
            sharing_with, to_device = alice.share_group_session(
                "!test:example.org",
                [BobId, MaloryId]
            )

        alice.blacklist_device(malory_device)
        sharing_with, to_device = alice.share_group_session(
            "!test:example.org",
            [BobId, MaloryId]
        )

        # check that we aren't sharing the group session with malory
        with pytest.raises(KeyError):
            to_device["messages"][MaloryId][malory_device.id]["ciphertext"]

        ciphertext = to_device["messages"][BobId][bob_device.id]["ciphertext"]

        olm_event_dict = {
            "sender": AliceId,
            "type": "m.room.encrypted",
            "content": {
                "algorithm": Olm._olm_algorithm,
                "sender_key": alice_device.curve25519,
                "ciphertext": ciphertext
            }
        }

        olm_event = OlmEvent.from_dict(olm_event_dict)

        assert isinstance(olm_event, OlmEvent)

        # bob decrypts the message and creates a new inbound session with alice
        try:
            # pdb.set_trace()
            bob.decrypt_event(olm_event)

            # we check that the session is there
            assert bob.session_store.get(alice_device.curve25519)
            # we check that the group session is there
            assert bob.inbound_group_store.get(
                "!test:example.org",
                alice_device.curve25519,
                group_session.id,
            )

            # Test another round of sharing, this time with an existing session
            alice.create_outbound_group_session(TEST_ROOM)
            group_session = alice.outbound_group_sessions[TEST_ROOM]

            sharing_with, to_device = alice.share_group_session(
                TEST_ROOM,
                [BobId, MaloryId]
            )

            ciphertext = to_device["messages"][BobId][bob_device.id]["ciphertext"]

            olm_event_dict = {
                "sender": AliceId,
                "type": "m.room.encrypted",
                "content": {
                    "algorithm": Olm._olm_algorithm,
                    "sender_key": alice_device.curve25519,
                    "ciphertext": ciphertext
                }
            }

            olm_event = OlmEvent.from_dict(olm_event_dict)
            assert isinstance(olm_event, OlmEvent)

            event = bob.decrypt_event(olm_event)
            assert event

            assert bob.inbound_group_store.get(
                TEST_ROOM,
                alice_device.curve25519,
                group_session.id,
            )

        finally:
            # remove the databases, the known devices store is handled by
            # monkeypatching
            os.remove(os.path.join(
                ephemeral_dir,
                "{}_{}.db".format(AliceId, Alice_device)
            ))
            os.remove(os.path.join(
                ephemeral_dir,
                "{}_{}.db".format(BobId, Bob_device)
            ))

    def test_group_session_sharing(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)

        # create three new accounts
        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)
        malory = self._load(BobId, Bob_device)

        # create olm devices for each others known devices list
        alice_device = OlmDevice(
            AliceId,
            Alice_device,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.account.identity_keys
        )

        malory_device = OlmDevice(
            MaloryId,
            Malory_device,
            malory.account.identity_keys
        )

        # add the devices to the device list
        alice.device_store.add(bob_device)
        alice.device_store.add(malory_device)
        bob.device_store.add(alice_device)

        # bob creates one time keys
        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        # Mark the keys as published
        bob.account.mark_keys_as_published()

        # alice creates an outbound olm session with bob
        alice.create_session(one_time, bob_device.curve25519)

        alice.verify_device(bob_device)
        alice.verify_device(malory_device)

        alice._maxToDeviceMessagesPerRequest = 1

        sharing_with, to_device = alice.share_group_session(
            "!test:example.org",
            [BobId, MaloryId]
        )
        group_session = alice.outbound_group_sessions["!test:example.org"]

        assert group_session

        assert len(sharing_with) == 1
        assert not group_session.users_shared_with

        group_session.users_shared_with.update(sharing_with)

        sharing_with, to_device = alice.share_group_session(
            "!test:example.org",
            [BobId, MaloryId]
        )

        assert len(sharing_with) == 1

        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(AliceId, Alice_device)
        ))
        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(BobId, Bob_device)
        ))

    @ephemeral
    def test_room_key_event(self):
        olm = self.ephemeral_olm

        session = OutboundGroupSession()

        payload = {
            "sender": BobId,
            "sender_device": Bob_device,
            "type": "m.room_key",
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "room_id": TEST_ROOM,
                "session_id": session.id,
                "session_key": session.session_key,
            },
            "keys": {
            }
        }

        bad_event = olm._handle_room_key_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            {}
        )

        assert isinstance(bad_event, UnknownBadEvent)

        event = olm._handle_room_key_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            payload
        )

        assert not event

        payload["keys"] = {
            "ed25519": "FEfrmWlasr4tcMtbNX/BU5lbdjmpt3ptg8ApTD8YAh4"
        }

        event = olm._handle_room_key_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            payload
        )

        assert isinstance(event, RoomKeyEvent)

    @ephemeral
    def test_forwarded_room_key_event(self):
        olm = self.ephemeral_olm

        session = OutboundGroupSession()
        session = InboundGroupSession(
            session.session_key,
            "FEfrmWlasr4tcMtbNX/BU5lbdjmpt3ptg8ApTD8YAh4",
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            TEST_ROOM
        )

        payload = {
            "sender": BobId,
            "sender_device": Bob_device,
            "type": "m.forwarded_room_key",
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "room_id": session.room_id,
                "session_id": session.id,
                "session_key": session.export_session(
                    session.first_known_index
                ),
                "sender_key": session.sender_key,
                "sender_claimed_ed25519_key": session.ed25519,
                "forwarding_curve25519_key_chain": session.forwarding_chain,
            },
            "keys": {
                "ed25519": session.ed25519
            }
        }

        bad_event = olm._handle_room_key_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            {}
        )
        assert isinstance(bad_event, UnknownBadEvent)

        event = olm._handle_forwarded_room_key_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            payload
        )
        assert not event

        key_request = OutgoingKeyRequest(
            session.id,
            session.id,
            session.room_id,
            "megolm.v1"
        )

        olm.outgoing_key_requests[session.id] = key_request
        event = olm._handle_olm_event(
            BobId,
            "Xjuu9d2KjHLGIHpCOCHS7hONQahapiwI1MhVmlPlCFM",
            payload
        )
        assert isinstance(event, ForwardedRoomKeyEvent)

    def test_user_verification_status(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)

        # create three new accounts
        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)

        # create olm devices for each others known devices list
        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.account.identity_keys
        )

        bob2_device = OlmDevice(
            BobId,
            Malory_device,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)

        assert not alice.user_fully_verified(BobId)

        alice.verify_device(bob_device)
        assert alice.user_fully_verified(BobId)

        alice.device_store.add(bob2_device)
        assert not alice.user_fully_verified(BobId)

        alice.verify_device(bob2_device)
        assert alice.user_fully_verified(BobId)

        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(AliceId, Alice_device)
        ))
        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(BobId, Bob_device)
        ))

    @ephemeral
    def test_group_decryption(self):
        olm = self.ephemeral_olm
        olm.create_outbound_group_session(TEST_ROOM)

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "hello wordl",
            },
        }

        with pytest.raises(GroupEncryptionError):
            encrypted_dict = olm.group_encrypt(TEST_ROOM, message)

        session = olm.outbound_group_sessions[TEST_ROOM]
        session.shared = True

        encrypted_dict = olm.group_encrypt(TEST_ROOM, message)

        megolm = {
            "type": "m.room.encrypted",
            "content": encrypted_dict
        }

        megolm_event = MegolmEvent.from_dict(megolm)
        assert isinstance(megolm_event, UnknownBadEvent)

        megolm["event_id"] = "1"
        megolm["sender"] = "@ephemeral:example.org"
        megolm["origin_server_ts"] = 0

        megolm_event = MegolmEvent.from_dict(megolm)

        assert isinstance(megolm_event, MegolmEvent)

        with pytest.raises(EncryptionError):
            event = olm.decrypt_megolm_event(megolm_event)

        session_store = olm.inbound_group_store
        olm.inbound_group_store = GroupSessionStore()

        with pytest.raises(EncryptionError):
            event = olm.decrypt_megolm_event(megolm_event)

        olm.inbound_group_store = session_store

        megolm_event.room_id = TEST_ROOM
        event = olm.decrypt_event(megolm_event)
        assert isinstance(event, RoomMessageText)
        assert event.decrypted

    @ephemeral
    def test_key_sharing(self):
        olm = self.ephemeral_olm

        assert olm.should_upload_keys
        to_share = olm.share_keys()

        assert "device_keys" in to_share
        assert "one_time_keys" in to_share
        assert len(to_share["one_time_keys"]) == olm.account.max_one_time_keys // 2

        response = KeysUploadResponse.from_dict({
            "one_time_key_counts": {
                "curve25519": 0,
                "signed_curve25519": olm.account.max_one_time_keys // 2
            }
        })

        olm.handle_response(response)

        assert not olm.should_upload_keys

        with pytest.raises(ValueError):
            to_share = olm.share_keys()

        olm.uploaded_key_count -= 1

        assert olm.should_upload_keys
        to_share = olm.share_keys()

        assert "device_keys" not in to_share
        assert "one_time_keys" in to_share
        assert len(to_share["one_time_keys"]) == 1

    def test_outbound_session_creation(self, monkeypatch):
        def mocksave(self):
            return

        monkeypatch.setattr(KeyStore, '_save', mocksave)

        alice = self._load(AliceId, Alice_device)
        bob = self._load(BobId, Bob_device)

        bob_device = OlmDevice(
            BobId,
            Bob_device,
            bob.account.identity_keys
        )

        assert not alice.get_missing_sessions([BobId])

        alice.device_store.add(bob_device)

        missing = alice.get_missing_sessions([BobId])
        assert not alice.session_store.get(bob_device.curve25519)

        assert BobId in missing
        assert Bob_device in missing[BobId]

        to_share = bob.share_keys()

        one_time_key = list(to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                BobId: {
                    Bob_device: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }

        response = KeysClaimResponse.from_dict(key_claim_dict, TEST_ROOM)

        assert isinstance(response, KeysClaimResponse)

        print(response)

        alice.handle_response(response)

        assert not alice.get_missing_sessions([BobId])
        assert alice.session_store.get(bob_device.curve25519)

        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(AliceId, Alice_device)
        ))
        os.remove(os.path.join(
            ephemeral_dir,
            "{}_{}.db".format(BobId, Bob_device)
        ))
