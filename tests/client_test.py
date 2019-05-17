# -*- coding: utf-8 -*-
import json

import pytest

from helpers import FrameFactory, ephemeral, ephemeral_dir, faker
from nio import (Client, DeviceList, DeviceOneTimeKeyCount, EncryptionError,
                 HttpClient, JoinedMembersResponse, KeysQueryResponse,
                 KeysUploadResponse, LocalProtocolError, LoginResponse,
                 MegolmEvent, RoomEncryptionEvent, RoomForgetResponse,
                 RoomInfo, RoomKeyRequestResponse, RoomMember, RoomMemberEvent,
                 Rooms, RoomSummary, ShareGroupSessionResponse, SyncResponse,
                 Timeline, TransportType, TypingNoticeEvent)
from nio.messages import ToDeviceMessage

HOST = "example.org"
USER = "example"
DEVICE_ID = "DEVICEID"

BOB_ID = "@bob:example.org"
TEST_ROOM_ID = "!testroom:example.org"

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"


class TestClass(object):
    example_response_headers = [
        (':status', '200'),
        ('server', 'fake-serv/0.1.0')
    ]

    @property
    def login_response(self):
        return LoginResponse("@ephemeral:example.org", "DEVICEID", "abc123")

    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    @staticmethod
    def _load_byte_response(filename):
        with open(filename, "rb") as f:
            return f.read()

    @property
    def login_byte_response(self):
        frame_factory = FrameFactory()

        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers, stream_id=1
        )

        login_body = json.dumps({
            "user_id": "@ephemeral:example.org",
            "access_token": "ABCD",
            "device_id": "DEVICEID",
        }).encode("utf-8")

        data = frame_factory.build_data_frame(
            data=login_body,
            stream_id=1,
            flags=['END_STREAM']
        )

        return f.serialize() + data.serialize()

    @property
    def sync_byte_response(self):
        frame_factory = FrameFactory()

        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers, stream_id=3
        )

        body = self._load_byte_response("tests/data/sync.json")

        data = frame_factory.build_data_frame(
            data=body,
            stream_id=3,
            flags=['END_STREAM']
        )

        return f.serialize() + data.serialize()

    def empty_response(self, stream_id=5):
        frame_factory = FrameFactory()

        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers, stream_id=stream_id
        )

        body = b"{}"

        data = frame_factory.build_data_frame(
            data=body,
            stream_id=stream_id,
            flags=['END_STREAM']
        )

        return f.serialize() + data.serialize()

    @property
    def sync_response(self):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    {"event_id": "event_id_1",
                     "sender": ALICE_ID,
                     "origin_server_ts": 1516809890615},
                    ALICE_ID,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent(
                    {
                        "event_id": "event_id_2",
                        "sender": ALICE_ID,
                        "origin_server_ts": 1516809890615
                    }
                )
            ],
            False,
            "prev_batch_token"
        )
        test_room_info = RoomInfo(
            timeline,
            [],
            [TypingNoticeEvent([ALICE_ID])],
            [],
            RoomSummary(1, 2, [])
        )
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
            [
                RoomEncryptionEvent(
                    {
                        "event_id": "event_id_2",
                        "sender": ALICE_ID,
                        "origin_server_ts": 1516809890615
                    }
                )
            ]
        )

    @property
    def downgrade_sync(self):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    {"event_id": "event_id_1",
                     "sender": ALICE_ID,
                     "origin_server_ts": 1516809890615},
                    ALICE_ID,
                    {"membership": "join"}
                ),
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
                    {"event_id": "event_id_1",
                     "sender": ALICE_ID,
                     "origin_server_ts": 1516809890615},
                    ALICE_ID,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent(
                    {
                        "event_id": "event_id_2",
                        "sender": ALICE_ID,
                        "origin_server_ts": 1516809890615
                    }
                )
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
        parsed_dict = TestClass._load_response(
            "tests/data/keys_query.json")
        return KeysQueryResponse.from_dict(parsed_dict)

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


    def test_device_store(self, tempdir):
        client = Client("ephemeral", "DEVICEID", tempdir)
        client.receive_response(self.login_response)
        client.receive_response(KeysUploadResponse(50, 50))

        assert not client.should_query_keys

        client.receive_response(self.sync_response)
        client.receive_response(self.keys_query_response)

        assert list(client.device_store.users) == [ALICE_ID]
        alice_device = client.device_store[ALICE_ID][ALICE_DEVICE_ID]
        assert alice_device

        client = Client("ephemeral", "DEVICEID", tempdir)
        client.receive_response(self.login_response)
        assert list(client.device_store.users) == [ALICE_ID]
        alice_device = client.device_store[ALICE_ID][ALICE_DEVICE_ID]
        assert alice_device

    def test_client_key_query(self, client):
        assert not client.should_query_keys

        client.receive_response(self.login_response)
        client.receive_response(KeysUploadResponse(50, 50))

        assert not client.should_query_keys
        client.receive_response(self.sync_response)

        assert not client.device_store.users

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

        assert not room.members_synced

        client.receive_response(self.joined_members)

        assert room.members_synced
        assert client.should_query_keys

        assert client.users_for_key_query == set([BOB_ID])

    @ephemeral
    def test_query_rule(self):
        client = Client("ephemeral", "DEVICEID", ephemeral_dir)
        client.receive_response(self.login_response)
        assert client.store is not None
        client.receive_response(KeysUploadResponse(50, 50))
        assert not client.should_query_keys

        client.receive_response(self.sync_response)
        assert client.should_query_keys
        client.receive_response(self.keys_query_response)
        assert client.olm.tracked_users == set([ALICE_ID])
        assert list(client.device_store.users) == [ALICE_ID]
        assert not client.should_query_keys

        del client

        client = Client("ephemeral", "DEVICEID", ephemeral_dir)
        client.receive_response(self.login_response)
        assert not client.should_upload_keys
        assert not client.should_query_keys

        assert list(client.device_store.users) == [ALICE_ID]
        assert client.device_store.active_user_devices(ALICE_ID)

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

    @ephemeral
    def test_early_store_loading(self):
        client = Client("ephemeral")

        with pytest.raises(LocalProtocolError):
            client.load_store()

        client = Client("ephemeral", store_path=ephemeral_dir)
        client.user_id = "@ephemeral:example.org"

        with pytest.raises(LocalProtocolError):
            client.load_store()

        client.user_id = None
        client.device_id = "DEVICEID"

        with pytest.raises(LocalProtocolError):
            client.load_store()

        client.receive_response(self.login_response)

        del client
        client = Client("ephemeral", "DEVICEID", ephemeral_dir)
        client.user_id = "@ephemeral:example.org"

        assert not client.store
        assert not client.olm

        client.load_store()
        assert client.store
        assert client.olm

    def test_makring_sessions_as_shared(self, client):
        client.receive_response(self.login_response)
        client.receive_response(self.sync_response)
        client.receive_response(self.joined_members)
        client.receive_response(self.keys_query_response)

        room = client.rooms[TEST_ROOM_ID]

        assert room.encrypted
        assert len(room.users) == 2
        assert ALICE_ID in client.device_store.users
        assert BOB_ID not in client.device_store.users

        with pytest.raises(EncryptionError):
            client.olm.share_group_session(TEST_ROOM_ID, room.users)

        shared_with, to_device = client.olm.share_group_session(
            TEST_ROOM_ID,
            room.users,
            True
        )

        session = client.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert (ALICE_ID, ALICE_DEVICE_ID) in session.users_ignored

        response = ShareGroupSessionResponse.from_dict({}, TEST_ROOM_ID, set())
        client.receive_response(response)

        assert session.shared

    def test_storing_room_encryption_state(self, client):
        client.receive_response(self.login_response)
        assert not client.encrypted_rooms

        client.receive_response(self.sync_response)
        assert TEST_ROOM_ID in client.encrypted_rooms

        encrypted_rooms = client.store.load_encrypted_rooms()
        assert TEST_ROOM_ID in encrypted_rooms

        client2 = Client(client.user, client.device_id, client.store_path)
        client2.receive_response(self.login_response)
        assert TEST_ROOM_ID in client2.encrypted_rooms

        client2.receive_response(self.downgrade_sync)
        room = client2.rooms[TEST_ROOM_ID]

        assert room.encrypted

    def test_http_client_login(self, http_client):
        http_client.connect(TransportType.HTTP2)

        _, _ = http_client.login("1234")

        http_client.receive(self.login_byte_response)
        response = http_client.next_response()

        assert isinstance(response, LoginResponse)
        assert http_client.access_token == "ABCD"

    def test_http_client_sync(self, http_client):
        http_client.connect(TransportType.HTTP2)

        _, _ = http_client.login("1234")

        http_client.receive(self.login_byte_response)
        response = http_client.next_response()

        assert isinstance(response, LoginResponse)
        assert http_client.access_token == "ABCD"

        _, _ = http_client.sync()

        http_client.receive(self.sync_byte_response)
        response = http_client.next_response()

        assert isinstance(response, SyncResponse)
        assert http_client.access_token == "ABCD"

    def test_http_client_keys_query(self, http_client):
        http_client.connect(TransportType.HTTP2)

        _, _ = http_client.login("1234")

        http_client.receive(self.login_byte_response)
        response = http_client.next_response()

        assert isinstance(response, LoginResponse)
        assert http_client.access_token == "ABCD"

        _, _ = http_client.sync()

        http_client.receive(self.sync_byte_response)
        response = http_client.next_response()

        assert isinstance(response, SyncResponse)
        assert http_client.access_token == "ABCD"

        event = MegolmEvent(
            "1",
            "@ephemeral:example.org.uk",
            0,
            "ABCD",
            "IDDEVICE",
            "test_session_id",
            "",
            http_client.olm._megolm_algorithm,
            TEST_ROOM_ID,
        )

        http_client.request_room_key(event)
        http_client.receive(self.empty_response(5))
        response = http_client.next_response()

        assert isinstance(response, RoomKeyRequestResponse)
        assert "test_session_id" in http_client.outgoing_key_requests


    def test_http_client_room_forget(self, http_client):
        http_client.connect(TransportType.HTTP2)

        _, _ = http_client.login("1234")

        http_client.receive(self.login_byte_response)
        response = http_client.next_response()

        assert isinstance(response, LoginResponse)
        assert http_client.access_token == "ABCD"

        _, _ = http_client.sync()

        http_client.receive(self.sync_byte_response)
        response = http_client.next_response()

        assert isinstance(response, SyncResponse)
        assert http_client.access_token == "ABCD"

        assert http_client.rooms
        room_id = list(http_client.rooms.keys())[0]
        _, _ = http_client.room_forget(room_id)

        http_client.receive(self.empty_response(5))
        response = http_client.next_response()

        assert isinstance(response, RoomForgetResponse)
        assert room_id not in http_client.rooms


    def test_event_callback(self, client):
        client.receive_response(self.login_response)

        class CallbackException(Exception):
            pass

        def cb(room, event):
            if isinstance(event, RoomMemberEvent):
                raise CallbackException()

        client.add_event_callback(cb, (RoomMemberEvent, RoomEncryptionEvent))

        with pytest.raises(CallbackException):
            client.receive_response(self.sync_response)

    def test_to_device_cb(self, client):
        client.receive_response(self.login_response)

        class CallbackException(Exception):
            pass

        def cb(event):
            if isinstance(event, RoomEncryptionEvent):
                raise CallbackException()

        client.add_to_device_callback(cb, RoomEncryptionEvent)

        with pytest.raises(CallbackException):
            client.receive_response(self.sync_response)

    def test_ephemeral_cb(self, client):
        client.receive_response(self.login_response)

        class CallbackException(Exception):
            pass

        def cb(_, event):
            raise CallbackException()

        client.add_ephermeral_callback(cb, TypingNoticeEvent)

        with pytest.raises(CallbackException):
            client.receive_response(self.sync_response)

    def test_no_encryption(self, client_no_e2e):
        client_no_e2e.receive_response(self.login_response)
        assert client_no_e2e.logged_in

        assert not client_no_e2e.olm
        client_no_e2e.receive_response(self.sync_response)

        assert len(client_no_e2e.rooms) == 1

        room = list(client_no_e2e.rooms.values())[0]

        assert room.encrypted
        client_no_e2e.receive_response(self.second_sync)

        with pytest.raises(LocalProtocolError):
            client_no_e2e.device_store

        with pytest.raises(LocalProtocolError):
            client_no_e2e.olm_account_shared

        not client_no_e2e.should_query_keys

        not client_no_e2e.users_for_key_query
        not client_no_e2e.key_verifications
        not client_no_e2e.outgoing_to_device_messages
        not client_no_e2e.get_active_sas(ALICE_ID, ALICE_DEVICE_ID)

        to_device = ToDeviceMessage("m.test", ALICE_ID, ALICE_DEVICE_ID, {})
        client_no_e2e._mark_to_device_message_as_sent(to_device)

        client_no_e2e.room_contains_unverified(room.room_id)

        with pytest.raises(LocalProtocolError):
            client_no_e2e.invalidate_outbound_session(room.room_id)

        client_no_e2e.receive_response(self.keys_query_response)
