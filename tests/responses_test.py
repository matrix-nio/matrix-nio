# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json

from nio.responses import (DeleteDevicesAuthResponse, DevicesResponse,
                           ErrorResponse, JoinedMembersError,
                           JoinedMembersResponse, KeysClaimResponse,
                           KeysQueryResponse, KeysUploadResponse, LoginError,
                           LoginResponse, PartialSyncResponse,
                           ProfileGetDisplayNameResponse, RoomKeyRequestError,
                           RoomKeyRequestResponse, RoomMessagesResponse,
                           SyncError, SyncResponse, ToDeviceError,
                           ToDeviceResponse, UploadResponse)

TEST_ROOM_ID = "!test:example.org"


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def test_login_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_response.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, LoginResponse)

    def test_login_failure_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_response_error.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, LoginError)

    def test_login_failure_format(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_invalid_format.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, ErrorResponse)

    def test_room_messages(self):
        parsed_dict = TestClass._load_response(
            "tests/data/room_messages.json")
        response = RoomMessagesResponse.from_dict(parsed_dict)
        assert isinstance(response, RoomMessagesResponse)

    def test_keys_upload(self):
        parsed_dict = TestClass._load_response(
            "tests/data/keys_upload.json")
        response = KeysUploadResponse.from_dict(parsed_dict)
        assert isinstance(response, KeysUploadResponse)

    def test_keys_query(self):
        parsed_dict = TestClass._load_response(
            "tests/data/keys_query.json")
        response = KeysQueryResponse.from_dict(parsed_dict)
        assert isinstance(response, KeysQueryResponse)

    def test_keys_claim(self):
        parsed_dict = TestClass._load_response(
            "tests/data/keys_claim.json")
        response = KeysClaimResponse.from_dict(
            parsed_dict,
            "!test:example.org"
        )
        assert isinstance(response, KeysClaimResponse)

    def test_devices(self):
        parsed_dict = TestClass._load_response(
            "tests/data/devices.json")
        response = DevicesResponse.from_dict(parsed_dict)
        assert isinstance(response, DevicesResponse)
        assert response.devices[0].id == "QBUAZIFURK"

    def test_delete_devices_auth(self):
        parsed_dict = TestClass._load_response(
            "tests/data/delete_devices.json")
        response = DeleteDevicesAuthResponse.from_dict(parsed_dict)
        assert isinstance(response, DeleteDevicesAuthResponse)
        assert response.session == "xxxxxxyz"

    def test_joined_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/joined_members_response.json")
        response = JoinedMembersResponse.from_dict(parsed_dict, "!testroom")
        assert isinstance(response, JoinedMembersResponse)

    def test_joined_fail(self):
        parsed_dict = {}
        response = JoinedMembersResponse.from_dict(parsed_dict, "!testroom")
        assert isinstance(response, JoinedMembersError)

    def test_upload_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/upload_response.json")
        response = UploadResponse.from_dict(parsed_dict)
        assert isinstance(response, UploadResponse)

    def test_sync_fail(self):
        parsed_dict = {}
        response = SyncResponse.from_dict(parsed_dict, 0)
        assert isinstance(response, SyncError)

    def test_sync_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/sync.json")
        response = SyncResponse.from_dict(parsed_dict)
        assert type(response) == SyncResponse

    def test_keyshare_request(self):
        parsed_dict = {
            "errcode": "M_LIMIT_EXCEEDED",
            "error": "Too many requests",
            "retry_after_ms": 2000
        }
        response = RoomKeyRequestResponse.from_dict(
            parsed_dict, "1", "1", TEST_ROOM_ID, "megolm.v1"
        )
        assert isinstance(response, RoomKeyRequestError)
        response = RoomKeyRequestResponse.from_dict(
                {}, "1", "1", TEST_ROOM_ID, "megolm.v1"
        )
        assert isinstance(response, RoomKeyRequestResponse)

    def test_partial_sync(self):
        parsed_dict = TestClass._load_response(
            "tests/data/sync.json")
        response = SyncResponse.from_dict(parsed_dict, 5)
        assert isinstance(response, PartialSyncResponse)
        assert len(
            response.rooms.join[
                "!SVkFJHzfwvuaIEawgC:localhost"
            ].timeline.events
        ) == 0
        assert len(
            response.rooms.join["!SVkFJHzfwvuaIEawgC:localhost"].state
        ) == 5

        new_response = response.next_part(1)
        assert isinstance(new_response, PartialSyncResponse)

        assert len(
            new_response.rooms.join[
                "!SVkFJHzfwvuaIEawgC:localhost"
            ].timeline.events
        ) == 0
        assert len(
            new_response.rooms.join["!SVkFJHzfwvuaIEawgC:localhost"].state
        ) == 1

        final_response = new_response.next_part()
        assert isinstance(final_response, SyncResponse)
        assert len(
            final_response.rooms.join[
                "!SVkFJHzfwvuaIEawgC:localhost"
            ].timeline.events
        ) == 1

    def test_get_displayname(self):
        parsed_dict = TestClass._load_response(
            "tests/data/get_displayname_response.json")
        response = ProfileGetDisplayNameResponse.from_dict(parsed_dict)
        assert isinstance(response, ProfileGetDisplayNameResponse)

    def test_to_device(self):
        message = "message"
        response = ToDeviceResponse.from_dict(
            {"error": "error", "errcode": "M_UNKNOWN"}, message
        )
        assert isinstance(response, ToDeviceError)
        response = ToDeviceResponse.from_dict({}, message)
        assert isinstance(response, ToDeviceResponse)
