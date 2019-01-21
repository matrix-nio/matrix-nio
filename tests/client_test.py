# -*- coding: utf-8 -*-
import pytest
from helpers import faker, ephemeral, ephemeral_dir

from nio import (
    Client,
    HttpClient,
    LocalProtocolError,
    LoginResponse,
    KeysUploadResponse,
    SyncResponse,
    DeviceList,
    DeviceOneTimeKeyCount,
    Rooms,
    RoomInfo,
    Timeline,
    RoomMemberEvent,
    RoomEncryptionEvent,
    RoomSummary,
    KeysQueryResponse,
    JoinedMembersResponse,
    RoomMember
)

HOST = "example.org"
USER = "example"
DEVICE_ID = "DEVICEID"

BOB_ID = "@bob:example.org"
TEST_ROOM_ID = "!testroom:example.org"

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"


class TestClass(object):
    @property
    def login_response(self):
        return LoginResponse("@ephemeral:example.org", "DEVICEID", "abc123")

    @property
    def sync_response(self):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    "event_id_1",
                    ALICE_ID,
                    1516809890615,
                    ALICE_ID,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent("event_id_2", ALICE_ID, 1516809890615)
            ],
            False,
            "prev_batch_token"
        )
        test_room_info = RoomInfo(timeline, [], [], [], RoomSummary(1, 2, []))
        rooms = Rooms(
            {},
            {
                TEST_ROOM_ID: test_room_info
            },
            {}
        )
        return SyncResponse(
            "token123",
            rooms,
            DeviceOneTimeKeyCount(49, 50),
            DeviceList([ALICE_ID], []),
            []
        )

    @property
    def second_sync(self):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    "event_id_1",
                    ALICE_ID,
                    1516809890615,
                    ALICE_ID,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent("event_id_2", ALICE_ID, 1516809890615)
            ],
            True,
            "prev_batch_token"
        )
        test_room_info = RoomInfo(timeline, [], [], [], RoomSummary(1, 2, []))
        rooms = Rooms(
            {},
            {
                TEST_ROOM_ID: test_room_info
            },
            {}
        )
        return SyncResponse(
            "token123",
            rooms,
            DeviceOneTimeKeyCount(49, 50),
            DeviceList([], []),
            []
        )

    @property
    def keys_query_response(self):
        return KeysQueryResponse(
            {
                "@alice:example.org": {
                    "JLAFKJWSCS": {
                        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                        "device_id": "JLAFKJWSCS",
                        "user_id": "@alice:example.org",
                        "keys": {
                            "curve25519:JLAFKJWSCS": "wjLpTLRqbqBzLs63aYaEv2Boi6cFEbbM/sSRQ2oAKk4",
                            "ed25519:JLAFKJWSCS": "nE6W2fCblxDcOFmeEtCHNl8/l8bXcu7GKyAswA4r3mM"
                        },
                        "signatures": {
                            "@alice:example.org": {
                                "ed25519:JLAFKJWSCS": "m53Wkbh2HXkc3vFApZvCrfXcX3AI51GsDHustMhKwlv3TuOJMj4wistcOTM8q2+e/Ro7rWFUb9ZfnNbwptSUBA"
                            }
                        }
                    }
                }
            },
            {},
        )

    @property
    def joined_members(self):
        return JoinedMembersResponse(
            [
                RoomMember(BOB_ID, None, None),
                RoomMember(ALICE_ID, None, None),
            ],
            TEST_ROOM_ID
        )

    def test_client_protocol_error(self):
        client = Client(USER, DEVICE_ID)

        with pytest.raises(LocalProtocolError):
            client.olm_account_shared

        with pytest.raises(LocalProtocolError):
            client.blacklist_device(faker.olm_device())

        with pytest.raises(LocalProtocolError):
            client.unblacklist_device(faker.olm_device())

        with pytest.raises(LocalProtocolError):
            client.verify_device(faker.olm_device())

        with pytest.raises(LocalProtocolError):
            client.unverify_device(faker.olm_device())

        with pytest.raises(LocalProtocolError):
            client.decrypt_event(None)

        with pytest.raises(LocalProtocolError):
            client.decrypt_event(None)

        with pytest.raises(LocalProtocolError):
            client.device_store

        client = HttpClient(HOST, USER, DEVICE_ID)

        with pytest.raises(LocalProtocolError):
            client.share_group_session(None)

        with pytest.raises(LocalProtocolError):
            client.keys_claim(None)

        with pytest.raises(LocalProtocolError):
            client.keys_query(None)

    def test_client_create(self, client):
        assert isinstance(client, Client)
        assert not client.store

    def test_client_invalid_response(self, client):
        with pytest.raises(ValueError):
            client.receive_response(None)

    def test_client_login(self, client):
        assert not client.access_token
        assert not client.store
        assert not client.olm

        client.receive_response(self.login_response)

        assert client.access_token
        assert client.store
        assert client.olm

    def test_client_account_sharing(self, client):
        client.receive_response(self.login_response)

        with pytest.raises(ValueError):
            client.decrypt_event(None)

        assert not client.olm_account_shared
        assert client.should_upload_keys
        assert client.device_store

        client.receive_response(KeysUploadResponse(49, 49))
        assert client.should_upload_keys
        client.receive_response(KeysUploadResponse(50, 50))
        assert not client.should_upload_keys

    def test_client_room_creation(self, client):
        client.receive_response(self.login_response)
        client.receive_response(KeysUploadResponse(50, 50))

        assert not client.should_query_keys
        client.receive_response(self.sync_response)

        assert client.rooms[TEST_ROOM_ID]
        room = client.rooms[TEST_ROOM_ID]

        assert room.encrypted
        assert client.should_query_keys

    def test_client_key_query(self, client):
        assert not client.should_query_keys

        client.receive_response(self.login_response)
        client.receive_response(KeysUploadResponse(50, 50))

        assert not client.should_query_keys
        client.receive_response(self.sync_response)

        assert client.rooms[TEST_ROOM_ID]
        room = client.rooms[TEST_ROOM_ID]

        assert room.encrypted
        assert room.summary
        assert len(room.users) == 1
        assert room.member_count == 2
        assert room.summary.joined_member_count == 2
        assert client.should_query_keys
        assert not client.device_store.users

        client.receive_response(self.keys_query_response)

        assert not client.should_query_keys
        assert client.device_store.users

        alice_device = client.device_store[ALICE_ID][ALICE_DEVICE_ID]
        assert alice_device

        assert not room.members_synced

        client.receive_response(self.joined_members)

        assert room.members_synced
        assert client.should_query_keys

        assert client.users_for_key_query == set([BOB_ID])

    def test_query_rule(self, tempdir):
        client = Client("ephemeral", "DEVICEID", tempdir)
        client.receive_response(self.login_response)
        client.receive_response(KeysUploadResponse(50, 50))
        assert not client.should_query_keys

        client.receive_response(self.sync_response)
        assert client.should_query_keys
        client.receive_response(self.keys_query_response)
        assert client.olm.tracked_users == set([ALICE_ID])
        assert not client.should_query_keys

        del client

        client = Client("ephemeral", "DEVICEID", tempdir)
        client.receive_response(self.login_response)
        assert not client.should_upload_keys
        assert not client.should_query_keys

        alice_device = client.device_store[ALICE_ID][ALICE_DEVICE_ID]
        assert alice_device

        client.receive_response(self.second_sync)
        assert client.should_query_keys

        client.users_for_key_query == set([ALICE_ID])

        client.receive_response(self.joined_members)

        client.users_for_key_query == set([ALICE_ID, BOB_ID])

        client.receive_response(self.keys_query_response)
        assert client.olm.tracked_users == set([ALICE_ID])
        assert client.users_for_key_query == set([BOB_ID])
        assert client.should_query_keys
