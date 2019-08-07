# -*- coding: utf-8 -*-

import copy
import json
import os
import time
from datetime import datetime, timedelta

import pytest
from olm import Account, OlmMessage, OlmPreKeyMessage, OutboundGroupSession

from nio.crypto import (DeviceStore, GroupSessionStore, InboundGroupSession,
                        Olm, OlmDevice, OutboundSession, OutgoingKeyRequest,
                        SessionStore, Session)
from nio.events import (ForwardedRoomKeyEvent, MegolmEvent, OlmEvent,
                        RoomKeyEvent, RoomMessageText, UnknownBadEvent,
                        ToDeviceEvent, DummyEvent, RoomKeyRequest,
                        RoomKeyRequestCancellation)
from nio.exceptions import EncryptionError, GroupEncryptionError, OlmTrustError
from nio.responses import (KeysClaimResponse, KeysQueryResponse,
                           KeysUploadResponse)
from nio.store import DefaultStore, Ed25519Key, Key, KeyStore

from helpers import faker

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


@pytest.fixture
def olm_account(tempdir):
    return Olm(
        faker.mx_id(),
        faker.device_id(),
        DefaultStore("ephemeral", "DEVICEID", tempdir)
    )


@pytest.fixture
def bob_account(tempdir):
    return Olm(
        faker.mx_id(),
        faker.device_id(),
        DefaultStore("ephemeral", "DEVICEID", tempdir)
    )


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def _get_store(self, user_id, device_id, pickle_key=""):
        return DefaultStore(user_id, device_id, ephemeral_dir, pickle_key)

    @staticmethod
    def olm_message_to_event(message_dict, recipient, sender):
        olm_content = message_dict["messages"][recipient.user_id][recipient.device_id]

        return {
            "sender": sender.user_id,
            "type": "m.room.encrypted",
            "content": olm_content,
        }

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

        if s.use_time > s2.use_time:
            assert s == store.get(curve_key)
        else:
            assert s2 == store.get(curve_key)

    def test_device_store(self):
        alice = OlmDevice(
            "example",
            "DEVICEID",
            {"ed25519": "2MX1WOCAmE9eyywGdiMsQ4RxL2SIKVeyJXiSjVFycpA",
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
            "m.megolm.v1.aes-sha2",
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

    def test_group_session_sharing_new(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        sharing_with, to_device = alice.share_group_session(
            "!test:example.org",
            [bob.user_id],
            ignore_unverified_devices=True
        )

        assert len(sharing_with) == 1
        assert alice.outbound_group_sessions["!test:example.org"]
        assert alice.is_device_ignored(bob_device)

    def test_session_unwedging(self, olm_account, bob_account):

        alice = olm_account
        bob = bob_account

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        # Let us pickle our session with bob here so we can later unpickle it
        # and wedge our session.
        alice_pickle = alice.session_store[bob_device.curve25519][0].pickle("")

        # Share a initial olm encrypted message
        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        outbound_session = alice.outbound_group_sessions[TEST_ROOM]

        olm_message = self.olm_message_to_event(to_device, bob, alice)

        # Pass the to-device event to bob and make sure we get the right events
        event = ToDeviceEvent.parse_event(olm_message)
        assert isinstance(event, OlmEvent)
        decrypted_event = bob.decrypt_event(event)
        assert isinstance(decrypted_event, RoomKeyEvent)

        # Make sure bob got the room-key
        assert bob.inbound_group_store
        bob_session = bob.inbound_group_store.get(
            TEST_ROOM,
            alice_device.curve25519,
            outbound_session.id
        )

        assert bob_session.id == outbound_session.id

        # Now bob shares a room-key with alice
        _, to_device = bob.share_group_session(
            TEST_ROOM,
            [alice.user_id],
            ignore_unverified_devices=True
        )

        olm_message = self.olm_message_to_event(to_device, alice, bob)
        event = ToDeviceEvent.parse_event(olm_message)
        assert isinstance(event, OlmEvent)
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomKeyEvent)

        # Let us wedge the session now
        session = alice.session_store[bob_device.curve25519][0]
        alice.session_store[bob_device.curve25519][0] = (
            Session.from_pickle(alice_pickle, session.creation_time, "",
                                session.use_time))

        alice.rotate_outbound_group_session(TEST_ROOM)

        # Try to share a room-key now
        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        # Set the creation time to be older than an hour, otherwise we will not
        # be able to unwedge the session.
        alice_session = bob.session_store.get(alice_device.curve25519)
        alice_session.creation_time = datetime.now() - timedelta(hours=2)

        olm_message = self.olm_message_to_event(to_device, bob, alice)
        # Pass the to-device event to bob and make sure we get the right events
        event = ToDeviceEvent.parse_event(olm_message)
        assert isinstance(event, OlmEvent)
        decrypted_event = bob.decrypt_event(event)

        # Make sure that decryption failed
        assert decrypted_event is None

        # Make sure that we have queued a m.dummy message to be sent out as a
        # to-device message

        assert alice_device in bob.wedged_devices

        # Bob should now claim new keys from alice, we're simulating this over
        # here since the olm machine doesn't know how to do requests.
        to_share = alice.share_keys()
        one_time_key = list(to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }

        response = KeysClaimResponse.from_dict(key_claim_dict, TEST_ROOM)

        assert not bob.outgoing_to_device_messages

        assert isinstance(response, KeysClaimResponse)
        bob.handle_response(response)

        # After we claimed the keys a new Olm session will be created and a
        # to-device message will be prepared for alice.
        assert bob.outgoing_to_device_messages

        message = bob.outgoing_to_device_messages[0]

        assert message.type == "m.room.encrypted"
        assert message.recipient == alice.user_id
        assert message.recipient_device == alice.device_id

        # Forward the message to alice.
        event = ToDeviceEvent.parse_event(
            self.olm_message_to_event(message.as_dict(), alice, bob)
        )

        assert isinstance(event, OlmEvent)

        # Take out our currently used session for bob.
        wedged_session = alice.session_store.get(bob_device.curve25519)
        decrypted_event = alice.decrypt_event(event)

        assert isinstance(decrypted_event, DummyEvent)

        # Check that the dummy event created a new Olm session and that it is
        # the preferred one.
        new_session = alice.session_store.get(bob_device.curve25519)
        assert wedged_session.use_time < new_session.use_time
        assert wedged_session != new_session

        # Try to mark the device again to be unwedged, this should fail since
        # our creation time isn't old enough.
        alice._mark_device_for_unwedging(alice_device.user_id,
                                         alice_device.curve25519)
        assert alice_device not in bob.wedged_devices

    def test_device_renaming(self, olm_account):
        parsed_dict = TestClass._load_response(
            "tests/data/keys_query.json")
        response = KeysQueryResponse.from_dict(parsed_dict)

        assert isinstance(response, KeysQueryResponse)

        olm_account.handle_response(response)
        device = olm_account.device_store["@alice:example.org"]["JLAFKJWSCS"]

        assert (
            device.ed25519 == "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM"
        )
        assert device.display_name == "Alice's mobile phone"

        parsed_dict["device_keys"]["@alice:example.org"]["JLAFKJWSCS"]["unsigned"]["device_display_name"] = "Phoney"

        response = KeysQueryResponse.from_dict(parsed_dict)
        olm_account.handle_response(response)
        assert device.display_name == "Phoney"

    def test_replay_attack_protection(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        # Share a initial olm encrypted message
        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        outbound_session = alice.outbound_group_sessions[TEST_ROOM]
        outbound_session.shared = True

        olm_message = self.olm_message_to_event(to_device, bob, alice)

        # Pass the to-device event to bob and make sure we get the right events
        event = ToDeviceEvent.parse_event(olm_message)
        assert isinstance(event, OlmEvent)
        decrypted_event = bob.decrypt_event(event)
        assert isinstance(decrypted_event, RoomKeyEvent)

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = alice.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": alice.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        decrypted_event = bob.decrypt_event(event)
        assert decrypted_event.body == message["content"]["body"]

        # Let us now replay the event.

        encrypted_message["event_id"] = "!new_event_id"
        event = MegolmEvent.from_dict(encrypted_message)

        with pytest.raises(EncryptionError):
            bob.decrypt_megolm_event(event)

        encrypted_message["event_id"] = "!event_id"
        old_time = encrypted_message["origin_server_ts"]
        encrypted_message["origin_server_ts"] += 100
        event = MegolmEvent.from_dict(encrypted_message)

        with pytest.raises(EncryptionError):
            bob.decrypt_megolm_event(event)

        # Let us now check that normal messages from the room history decrypt
        # again.
        encrypted_message["origin_server_ts"] = old_time
        event = MegolmEvent.from_dict(encrypted_message)

        decrypted_event = bob.decrypt_event(event)

        assert decrypted_event.body == message["content"]["body"]

    def test_key_forwards(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        # Setup a working olm session by sharing a key from alice to bob
        olm_message = self.olm_message_to_event(to_device, bob, alice)
        event = ToDeviceEvent.parse_event(olm_message)
        bob.decrypt_event(event)

        # Bob shares a room session as well but alice never receives the
        # session.
        bob.share_group_session(
            TEST_ROOM,
            [alice.user_id],
            ignore_unverified_devices=True
        )

        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True
        session.users_shared_with.add((alice.user_id, alice.device_id))

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        # Bob receives the event and queues it up for collection.
        bob.handle_to_device_event(key_request_event)

        assert key_request_event in bob.received_key_requests.values()

        # Convert the key request event into a to-device message.
        bob.collect_key_requests()
        # Check that the message is now queued.
        assert bob.outgoing_to_device_messages

        to_device = bob.outgoing_to_device_messages[0]

        # Let us now share the to-device message with Alice
        olm_message = self.olm_message_to_event(to_device.as_dict(), alice,
                                                bob)
        forwarded_key_event = ToDeviceEvent.parse_event(olm_message)

        assert isinstance(forwarded_key_event, OlmEvent)

        # Decrypt the olm event and check that we received a forwarded room
        # key.
        decrypted_event = alice.handle_to_device_event(forwarded_key_event)
        assert isinstance(decrypted_event, ForwardedRoomKeyEvent)

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    def test_key_forwards_with_ourselves(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account
        bob.user_id = alice.user_id

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)
        bob.verify_device(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        # Setup a working olm session by sharing a key from alice to bob
        olm_message = self.olm_message_to_event(to_device, bob, alice)
        event = ToDeviceEvent.parse_event(olm_message)
        bob.decrypt_event(event)

        # Bob shares a room session as well but alice never receives the
        # session.
        bob.share_group_session(
            TEST_ROOM,
            [alice.user_id],
            ignore_unverified_devices=True
        )

        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True
        session.users_shared_with.add((alice.user_id, alice.device_id))

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        # Bob receives the event and queues it up for collection.
        bob.handle_to_device_event(key_request_event)

        assert key_request_event in bob.received_key_requests.values()

        # Convert the key request event into a to-device message.
        bob.collect_key_requests()
        # Check that the message is now queued.
        assert bob.outgoing_to_device_messages

        to_device = bob.outgoing_to_device_messages[0]

        # Let us now share the to-device message with Alice
        olm_message = self.olm_message_to_event(to_device.as_dict(), alice,
                                                bob)
        forwarded_key_event = ToDeviceEvent.parse_event(olm_message)

        assert isinstance(forwarded_key_event, OlmEvent)

        # Decrypt the olm event and check that we received a forwarded room
        # key.
        decrypted_event = alice.handle_to_device_event(forwarded_key_event)
        assert isinstance(decrypted_event, ForwardedRoomKeyEvent)

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    def test_key_forwards_missing_session(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account
        bob.user_id = alice.user_id

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)
        bob.verify_device(alice_device)

        bob.create_outbound_group_session(TEST_ROOM)
        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        # Bob receives the event and queues it up for collection.
        bob.handle_to_device_event(key_request_event)

        assert key_request_event in bob.received_key_requests.values()

        # Convert the key request event into a to-device message.
        bob.collect_key_requests()
        # Check that the message is not queued. We are missing a Olm session.
        assert not bob.outgoing_to_device_messages

        assert alice_device in bob.key_request_devices_no_session
        assert (
            key_request_event in
            bob.key_requests_waiting_for_session[alice_device.user_id, alice_device.id].values()
        )

        # Let us do a key claim request.
        to_share = alice.share_keys()
        one_time_key = list(to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }

        response = KeysClaimResponse.from_dict(key_claim_dict)
        bob.handle_response(response)

        # We got a session now, the device is not waiting for a session anymore
        assert alice_device not in bob.key_request_devices_no_session
        # The key request is neither waiting for a session anymore.
        assert (
            key_request_event not in
            bob.key_requests_waiting_for_session[alice_device.user_id, alice_device.id].values()
        )
        # The key request is now waiting to be collected again.
        assert key_request_event in bob.received_key_requests.values()

        # Let us collect it now.
        bob.collect_key_requests()

        # We found a to-device message now.
        to_device = bob.outgoing_to_device_messages[0]

        # Let us now share the to-device message with Alice
        olm_message = self.olm_message_to_event(to_device.as_dict(), alice,
                                                bob)
        forwarded_key_event = ToDeviceEvent.parse_event(olm_message)

        assert isinstance(forwarded_key_event, OlmEvent)

        # Decrypt the olm event and check that we received a forwarded room
        # key.
        decrypted_event = alice.handle_to_device_event(forwarded_key_event)
        assert isinstance(decrypted_event, ForwardedRoomKeyEvent)

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    def test_key_forward_untrusted_device(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account
        bob.user_id = alice.user_id

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)

        bob.account.generate_one_time_keys(1)
        one_time = list(bob.account.one_time_keys["curve25519"].values())[0]
        bob.account.mark_keys_as_published()

        alice.create_session(one_time, bob_device.curve25519)

        _, to_device = alice.share_group_session(
            TEST_ROOM,
            [bob.user_id],
            ignore_unverified_devices=True
        )

        # Setup a working olm session by sharing a key from alice to bob
        olm_message = self.olm_message_to_event(to_device, bob, alice)
        event = ToDeviceEvent.parse_event(olm_message)
        bob.decrypt_event(event)

        # Bob shares a room session as well but alice never receives the
        # session.
        bob.share_group_session(
            TEST_ROOM,
            [alice.user_id],
            ignore_unverified_devices=True
        )

        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True
        session.users_shared_with.add((alice.user_id, alice.device_id))

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        # Bob receives the event and queues it up for collection.
        bob.handle_to_device_event(key_request_event)

        assert key_request_event in bob.received_key_requests.values()

        # Convert the key request event into a to-device message.
        collected_requests = bob.collect_key_requests()
        # The message could not be queued because the device is not trusted
        assert not bob.outgoing_to_device_messages
        assert key_request_event in bob.key_request_from_untrusted.values()
        assert key_request_event in collected_requests

        # Let us try to continue the key share without verifying the device.
        assert not bob.continue_key_share(key_request_event)

        # Let us now verify the device and tell our Olm machine that we should
        # resume.
        bob.verify_device(alice_device)
        assert bob.continue_key_share(key_request_event)
        assert key_request_event not in bob.key_request_from_untrusted.values()

        # There is now a key queued up to be sent as a to-device message.
        assert bob.outgoing_to_device_messages
        to_device = bob.outgoing_to_device_messages[0]

        # Let us now share the to-device message with Alice
        olm_message = self.olm_message_to_event(to_device.as_dict(), alice,
                                                bob)
        forwarded_key_event = ToDeviceEvent.parse_event(olm_message)

        assert isinstance(forwarded_key_event, OlmEvent)

        # Decrypt the olm event and check that we received a forwarded room
        # key.
        decrypted_event = alice.handle_to_device_event(forwarded_key_event)
        assert isinstance(decrypted_event, ForwardedRoomKeyEvent)

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    def test_key_forward_cancelling(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account
        bob.user_id = alice.user_id

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)
        # bob.verify_device(alice_device)

        bob.create_outbound_group_session(TEST_ROOM)
        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        cancellation = RoomKeyRequestCancellation(
            {},
            key_request_event.sender,
            key_request_event.requesting_device_id,
            key_request_event.request_id,
        )

        # Bob receives the event and queues it up for collection.
        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        # Cancel the request immediatelly.
        bob.handle_to_device_event(cancellation)
        assert key_request_event not in bob.received_key_requests.values()

        # Bob receives the event again
        bob.handle_to_device_event(key_request_event)

        # This time we collect the event.
        assert cancellation not in bob.collect_key_requests()
        # Check that the message is not queued. We are missing a Olm session.
        assert not bob.outgoing_to_device_messages

        assert alice_device in bob.key_request_devices_no_session
        assert (
            key_request_event in
            bob.key_requests_waiting_for_session[alice_device.user_id, alice_device.id].values()
        )

        # We cancel again.
        bob.handle_to_device_event(cancellation)
        assert cancellation not in bob.collect_key_requests()

        assert alice_device not in bob.key_request_devices_no_session
        assert (
            key_request_event not in
            bob.key_requests_waiting_for_session[alice_device.user_id, alice_device.id].values()
        )

        # Let us do another round
        bob.handle_to_device_event(key_request_event)
        bob.collect_key_requests()

        # Let us do a key claim request.
        to_share = alice.share_keys()
        one_time_key = list(to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }

        response = KeysClaimResponse.from_dict(key_claim_dict)
        bob.handle_response(response)

        # We got a session now, the device is not waiting for a session anymore
        assert alice_device not in bob.key_request_devices_no_session
        # The key request is neither waiting for a session anymore.
        assert (
            key_request_event not in
            bob.key_requests_waiting_for_session[alice_device.user_id, alice_device.id].values()
        )
        # The key request is now waiting to be collected again.
        assert key_request_event in bob.received_key_requests.values()

        # Let us collect it now.
        bob.collect_key_requests()

        # Still no, device isn't verified.
        assert not bob.outgoing_to_device_messages
        assert key_request_event in bob.key_request_from_untrusted.values()

        # Cancel again, now we're going to get the cancellation event in the
        # collect output
        bob.handle_to_device_event(cancellation)
        assert cancellation in bob.collect_key_requests()

        # Let us finally check out if bob can also reject the sharing of the
        # key.
        bob.handle_to_device_event(key_request_event)
        event_for_user = bob.collect_key_requests()[0]
        assert not bob.outgoing_to_device_messages
        assert key_request_event in bob.key_request_from_untrusted.values()

        assert bob.cancel_key_share(event_for_user)
        assert key_request_event not in bob.key_request_from_untrusted.values()

    def test_invalid_key_requests(self, olm_account, bob_account):
        alice = olm_account
        bob = bob_account

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.account.identity_keys
        )

        alice.device_store.add(bob_device)
        bob.device_store.add(alice_device)
        # bob.verify_device(alice_device)

        bob.create_outbound_group_session(TEST_ROOM)
        session = bob.outbound_group_sessions[TEST_ROOM]
        session.shared = True

        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.group_encrypt(TEST_ROOM, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM
        }
        event = MegolmEvent.from_dict(encrypted_message)

        # Alice tries to decrypt the event but can't.
        decrypted_event = alice.decrypt_event(event)
        assert decrypted_event is None

        key_request = event.as_key_request(
            bob.user_id,
            alice.device_id,
            event.session_id,
        )

        outgoing_key_request = OutgoingKeyRequest(
            event.session_id,
            event.session_id,
            TEST_ROOM,
            event.algorithm
        )

        alice.outgoing_key_requests[event.session_id] = outgoing_key_request

        key_request = {
            "sender": alice.user_id,
            "type": "m.room_key_request",
            "content": key_request.as_dict()["messages"][bob.user_id]["*"]
        }

        key_request_event = RoomKeyRequest.from_dict(key_request)

        assert isinstance(key_request_event, RoomKeyRequest)

        assert not bob.outgoing_to_device_messages

        key_request_event.session_id = "fake_id"

        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        assert not bob.outgoing_to_device_messages
        bob.collect_key_requests()
        assert not bob.outgoing_to_device_messages

        key_request_event.session_id = session.id
        key_request_event.requesting_device_id = "FAKE_ID"

        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        assert not bob.outgoing_to_device_messages
        bob.collect_key_requests()
        assert not bob.outgoing_to_device_messages

        alice_device.deleted = True
        key_request_event.requesting_device_id = alice.device_id

        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        assert not bob.outgoing_to_device_messages
        bob.collect_key_requests()
        assert not bob.outgoing_to_device_messages

        bob.user_id = alice.user_id

        key_request_event.session_id = "fake_id"
        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        assert not bob.outgoing_to_device_messages
        bob.collect_key_requests()
        assert not bob.outgoing_to_device_messages

        key_request_event.session_id = session.id
        key_request_event.requesting_device_id = "FAKE_ID"

        bob.handle_to_device_event(key_request_event)
        assert key_request_event in bob.received_key_requests.values()
        assert not bob.outgoing_to_device_messages
        bob.collect_key_requests()
        assert not bob.outgoing_to_device_messages
