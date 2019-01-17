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
    RoomEncryptionEvent
)

HOST = "example.org"
USER = "example"
DEVICE_ID = "DEVICEID"

BOB_ID = "@bob:example.org"
TEST_ROOM_ID = "!testroom:example.org"


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
                    BOB_ID,
                    1516809890615,
                    BOB_ID,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent("event_id_2", BOB_ID, 1516809890615)
            ],
            False,
            "prev_batch_token"
        )
        test_room_info = RoomInfo(timeline, [], [], [], None)
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
            DeviceList([BOB_ID], []),
            []
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
