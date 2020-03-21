import json
import math
import sys
import re
import time
from pathlib import Path
from os import path
from datetime import datetime, timedelta
from urllib.parse import quote
from uuid import uuid4

import aiofiles
import pytest
from aiohttp import (ClientRequest, ClientSession, ClientTimeout,
                     TraceRequestChunkSentParams)
from yarl import URL

from helpers import faker
from nio import (ContentRepositoryConfigResponse,
                 DeviceList, DeviceOneTimeKeyCount, DownloadError,
                 DevicesResponse, DeleteDevicesAuthResponse,
                 DeleteDevicesResponse,
                 DownloadResponse, ErrorResponse,
                 GroupEncryptionError,
                 JoinResponse, JoinedRoomsResponse,
                 JoinedMembersResponse, KeysClaimResponse, KeysQueryResponse,
                 KeysUploadResponse, LocalProtocolError, LoginError,
                 LoginResponse, LogoutError, LogoutResponse,
                 MegolmEvent, MembersSyncError, OlmTrustError,
                 RoomContextResponse, RoomForgetResponse,
                 ProfileGetAvatarResponse,
                 ProfileGetDisplayNameResponse, ProfileGetResponse,
                 ProfileSetAvatarResponse, ProfileSetDisplayNameResponse,
                 RoomTypingResponse, RoomCreateResponse,
                 RoomEncryptionEvent, RoomInfo, RoomLeaveResponse,
                 RoomInviteResponse,
                 RoomMemberEvent, RoomMessagesResponse, Rooms,
                 RoomGetStateResponse, RoomGetStateEventResponse,
                 RoomPutStateResponse,
                 RoomRedactResponse, RoomResolveAliasResponse,
                 RoomSendResponse, RoomSummary,
                 ShareGroupSessionResponse,
                 SyncResponse, ThumbnailError, ThumbnailResponse,
                 Timeline, TransferMonitor, TransferCancelledError,
                 UploadResponse,
                 RoomMessageText, RoomKeyRequest)
from nio.api import ResizingMethod, RoomPreset, RoomVisibility
from nio.crypto import OlmDevice, Session, decrypt_attachment
from nio.client.async_client import connect_wrapper, on_request_chunk_sent

from aioresponses import CallbackResult

TEST_ROOM_ID = "!testroom:example.org"

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"

CAROL_ID = "@carol:example.org"

if sys.version_info >= (3, 5):
    import asyncio
    from nio import AsyncClient, AsyncClientConfig


@pytest.mark.skipif(sys.version_info < (3, 5), reason="Python 3 specific asyncio tests")
class TestClass(object):
    @staticmethod
    def _load_bytes(filename):
        with open(filename, "rb") as f:
            return f.read()

    @staticmethod
    def olm_message_to_event(message_dict, recipient, sender, type="m.room.encrypted"):
        olm_content = message_dict["messages"][recipient.user_id][recipient.device_id]

        return {
            "sender": sender.user_id,
            "type": type,
            "content": olm_content,
        }


    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read())

    @property
    def login_response(self):
        return self._load_response("tests/data/login_response.json")

    @property
    def logout_response(self):
        return self._load_response("tests/data/logout_response.json")

    @property
    def keys_upload_response(self):
        return self._load_response("tests/data/keys_upload.json")

    @property
    def sync_response(self):
        return self._load_response("tests/data/sync.json")

    @property
    def context_response(self):
        return self._load_response("tests/data/context.json")

    @property
    def messages_response(self):
        return self._load_response("tests/data/room_messages.json")

    @property
    def keys_query_response(self):
        return self._load_response(
            "tests/data/keys_query.json")

    @property
    def joined_members_response(self):
        return {
            "joined": {  # joined
                "@bar:example.com": {
                    "avatar_url": None,
                    "display_name": "Bar"
                },
                ALICE_ID: {  # joined
                    "avatar_url": None,
                    "display_name": "Alice"
                },
                CAROL_ID: {  # invited
                    "avatar_url": None,
                    "display_name": "Carol"
                },
            }}

    @property
    def joined_rooms_response(self):
        return {
            "joined_rooms": [TEST_ROOM_ID]
        }

    @property
    def room_get_state_response(self):
        return self._load_response(
            "tests/data/room_state.json")

    @property
    def encryption_sync_response(self):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    {"event_id": "event_id_1",
                     "sender": ALICE_ID,
                     "origin_server_ts": 1516809890615},
                    ALICE_ID,
                    "join",
                    None,
                    {"membership": "join"}
                ),
                RoomMemberEvent(
                    {"event_id": "event_id_2",
                     "sender": ALICE_ID,
                     "origin_server_ts": 1516809890615},
                    CAROL_ID,
                    "invite",
                    None,
                    {"membership": "invite"}
                ),
                RoomEncryptionEvent(
                    {
                        "event_id": "event_id_3",
                        "sender": ALICE_ID,
                        "origin_server_ts": 1516809890615
                    }
                )
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

    def synce_response_for(self, own_user, other_user):
        timeline = Timeline(
            [
                RoomMemberEvent(
                    {"event_id": "event_id_1",
                     "sender": own_user,
                     "origin_server_ts": 1516809890615},
                    own_user,
                    "join",
                    None,
                    {"membership": "join"}
                ),
                RoomMemberEvent(
                    {"event_id": "event_id_1",
                     "sender": other_user,
                     "origin_server_ts": 1516809890615},
                    other_user,
                    "join",
                    None,
                    {"membership": "join"}
                ),
                RoomEncryptionEvent(
                    {
                        "event_id": "event_id_2",
                        "sender": other_user,
                        "origin_server_ts": 1516809890615
                    }
                )
            ],
            False,
            "prev_batch_token"
        )
        test_room_info = RoomInfo(timeline, [], [], [], RoomSummary(0, 2, []))
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
            DeviceOneTimeKeyCount(50, 50),
            DeviceList([other_user], []),
            []
        )

    @property
    def empty_sync(self):
        return {
            "account_data": {
                "events": []
            },
            "device_lists": {
                "changed": [],
                "left": []
            },
            "device_one_time_keys_count": {
                "signed_curve25519": 50
            },
            "groups": {
                "invite": {},
                "join": {},
                "leave": {}
            },
            "next_batch": "s1059_133339_44_763_246_1_586_12411_1",
            "presence": {
                "events": []
            },
            "rooms": {
                "invite": {},
                "join": {},
                "leave": {}
            },
            "to_device": {
                "events": []
            }
        }

    def sync_with_to_device_events(self, event, sync_token=None):
        response = self.empty_sync
        response["to_device"]["events"].append(event)

        if sync_token:
            response["next_batch"] += sync_token

        return response

    def sync_with_room_event(self, event, sync_token=None):
        response = self.empty_sync
        response["rooms"]["join"][TEST_ROOM_ID] = {
            "timeline": {
                "events": [event],
                "limited": False,
                "prev_batch": "12345"
            },
            "state": {"events": []},
            "ephemeral": {"events": []},
            "account_data": {"events": []}
        }

        if sync_token:
            response["next_batch"] += sync_token

        return response


    @property
    def limit_exceeded_error_response(self):
        return self._load_response("tests/data/limit_exceeded_error.json")

    @property
    def upload_response(self):
        return self._load_response("tests/data/upload_response.json")

    @property
    def file_response(self):
        return self._load_bytes("tests/data/file_response")

    @staticmethod
    def room_id_response(room_id):
        return {"room_id": room_id}

    @staticmethod
    def get_profile_response(displayname, avatar_url):
        return {"displayname": displayname, "avatar_url": avatar_url}

    @staticmethod
    def get_displayname_response(displayname):
        return {"displayname": displayname}

    @staticmethod
    def get_avatar_response(avatar_url):
        return {"avatar_url": avatar_url}

    @property
    def room_resolve_alias_response(self):
        return {
            "room_id": TEST_ROOM_ID,
            "servers": ["example.org", "matrix.org"]
        }

    async def test_mxc_to_http(self, async_client):
        mxc      = "mxc://privacytools.io/123foo"
        url_path = "/_matrix/media/r0/download/privacytools.io/123foo"

        async_client.homeserver = "https://chat.privacytools.io"
        expected                = f"{async_client.homeserver}{url_path}"
        assert await async_client.mxc_to_http(mxc) == expected

        other_server = "http://localhost:8081"
        expected     = f"{other_server}{url_path}"
        assert await async_client.mxc_to_http(mxc, other_server) == expected

    def test_login(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        resp = loop.run_until_complete(async_client.login("wordpass"))

        assert isinstance(resp, LoginResponse)
        assert async_client.access_token
        assert async_client.logged_in

    def test_failed_login(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=400,
            body=""
        )
        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert isinstance(resp, LoginError)
        assert not async_client.logged_in

        assert async_client.client_session
        loop.run_until_complete(async_client.close())
        assert not async_client.client_session

    def test_login_raw(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        auth_dict = {
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.thirdparty",
                "medium": "email",
                "address": "testemail@mail.org"
            },
            "password": "PASSWORDABCD",
            "initial_device_display_name": "Test user"
        }
        resp = loop.run_until_complete(
            async_client.login_raw(
                auth_dict
            )
        )

        assert isinstance(resp, LoginResponse)
        assert async_client.access_token
        assert async_client.logged_in

    def test_failed_login_raw(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=400,
            body=""
        )

        auth_dict = {
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.thirdparty",
                "medium": "email",
                "address": "testemail@mail.org"
            },
            "password": "WRONGPASSWORD",
            "initial_device_display_name": "Test user"
        }

        resp = loop.run_until_complete(
            async_client.login_raw(auth_dict)
        )

        assert isinstance(resp, LoginError)
        assert not async_client.logged_in

        assert async_client.client_session
        loop.run_until_complete(async_client.close())
        assert not async_client.client_session

    def test_login_raw_with_empty_dict(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        auth_dict = {}
        resp = None

        with pytest.raises(ValueError):
            resp = loop.run_until_complete(
                async_client.login_raw(auth_dict)
            )

        assert not resp
        assert not async_client.logged_in

        assert not async_client.client_session
        loop.run_until_complete(async_client.close())
        assert not async_client.client_session

    def test_login_raw_with_none_dict(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        auth_dict = None
        resp = None

        with pytest.raises(ValueError):
            resp = loop.run_until_complete(
                async_client.login_raw(auth_dict)
            )

        assert not resp
        assert not async_client.logged_in

        assert not async_client.client_session
        loop.run_until_complete(async_client.close())
        assert not async_client.client_session

    def test_logout(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/logout?access_token=abc123",
            status=200,
            payload=self.logout_response
        )

        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert async_client.access_token
        assert async_client.logged_in
        resp2 = loop.run_until_complete(async_client.logout())

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, LogoutResponse)
        assert not async_client.access_token
        assert not async_client.logged_in

    def test_failed_logout(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/logout?access_token=abc123",
            status=400,
            body=""
        )

        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert async_client.access_token
        assert async_client.logged_in
        resp2 = loop.run_until_complete(async_client.logout())

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, LogoutError)
        assert async_client.access_token
        assert async_client.logged_in

    def test_logout_all_devices(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/logout/all?access_token=abc123",
            status=200,
            payload=self.logout_response
        )

        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert async_client.access_token
        assert async_client.logged_in
        resp2 = loop.run_until_complete(async_client.logout(all_devices=True))

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, LogoutResponse)
        assert not async_client.access_token
        assert not async_client.logged_in

    def test_failed_logout_all_devices(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/logout/all?access_token=abc123",
            status=400,
            body=""
        )

        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert async_client.access_token
        assert async_client.logged_in
        resp2 = loop.run_until_complete(async_client.logout(all_devices=True))

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, LogoutError)
        assert async_client.access_token
        assert async_client.logged_in

    def test_sync(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        aioresponse.get(
            "https://example.org/_matrix/client/r0/sync?access_token=abc123",
            status=200,
            payload=self.sync_response
        )
        with pytest.raises(LocalProtocolError):
            resp2 = loop.run_until_complete(async_client.sync())

        resp = loop.run_until_complete(async_client.login("wordpass"))
        resp2 = loop.run_until_complete(async_client.sync())

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, SyncResponse)

    def test_keys_upload(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        with pytest.raises(LocalProtocolError):
            resp2 = loop.run_until_complete(async_client.keys_upload())

        assert not async_client.should_upload_keys

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/upload?access_token=abc123",
            status=200,
            payload=self.keys_upload_response
        )

        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert async_client.should_upload_keys
        assert not async_client.olm_account_shared

        resp2 = loop.run_until_complete(async_client.keys_upload())

        assert isinstance(resp2, KeysUploadResponse)
        assert async_client.olm_account_shared
        assert async_client.should_upload_keys

    async def test_keys_query(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response
        )

        await async_client.login("wordpass")
        assert not async_client.should_query_keys

        await async_client.receive_response(self.encryption_sync_response)
        assert async_client.should_query_keys

        await async_client.keys_query()
        assert not async_client.should_query_keys

    async def test_message_sending(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        aioresponse.put(
                "https://example.org/_matrix/client/r0/rooms/!testroom:example.org/send/m.room.encrypted/1?access_token=abc123",
            status=200,
            payload={"event_id": "$1555:example.org"}
        )
        aioresponse.get(
            "https://example.org/_matrix/client/r0/rooms/{}/"
            "joined_members?access_token=abc123".format(TEST_ROOM_ID),
            status=200,
            payload=self.joined_members_response
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response
        )

        await async_client.login("wordpass")

        await async_client.receive_response(self.encryption_sync_response)

        response = await async_client.joined_members(TEST_ROOM_ID)

        async_client.olm.create_outbound_group_session(TEST_ROOM_ID)
        async_client.olm.outbound_group_sessions[TEST_ROOM_ID].shared = True

        response = await async_client.room_send(
            TEST_ROOM_ID,
            "m.room.message",
            {"body": "hello"},
            "1"
        )

        assert isinstance(response, RoomSendResponse)

    async def test_room_put_state(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"

        aioresponse.put(
            "{base}/rooms/{room}/state/{event}/{key}?{query}".format(
                base = base_url,
                room = TEST_ROOM_ID,
                event = "org.example.event_type",
                key = "",
                query = "access_token=abc123"
            ),
            status = 200,
            payload={"event_id": "$1337stateeventid2342:example.org"}
        )

        resp = await async_client.room_put_state(
                TEST_ROOM_ID,
                "org.example.event_type",
                {}
        )

        assert isinstance(resp, RoomPutStateResponse)


    async def test_room_get_state_event(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"
        path = "{base}/rooms/{room}/state/{event}/{key}?{query}".format(
            base = base_url,
            room = TEST_ROOM_ID,
            event = "m.room.name",
            key = "",
            query = "access_token=abc123"
        )

        aioresponse.get(
            path,
            status = 200,
            payload={"name": "Test Room"}
        )

        resp = await async_client.room_get_state_event(
                TEST_ROOM_ID,
                "m.room.name"
        )

        assert isinstance(resp, RoomGetStateEventResponse)


    async def test_room_get_state(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"

        aioresponse.get(
            "{base}/rooms/{room}/state?{query}".format(
                base = base_url,
                room = TEST_ROOM_ID,
                query = "access_token=abc123"
            ),
            status = 200,
            payload=self.room_get_state_response
        )

        resp = await async_client.room_get_state(
                TEST_ROOM_ID,
        )

        assert isinstance(resp, RoomGetStateResponse)


    def keys_claim_dict(self, client):
        to_share = client.olm.share_keys()
        one_time_key = list(to_share["one_time_keys"].items())[0]
        return {
            "one_time_keys": {
                ALICE_ID: {
                    ALICE_DEVICE_ID: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }


    async def test_key_claiming(self, alice_client, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        await async_client.receive_response(self.encryption_sync_response)

        alice_client.load_store()
        alice_device = OlmDevice(
            ALICE_ID,
            ALICE_DEVICE_ID,
            alice_client.olm.account.identity_keys
        )

        async_client.device_store.add(alice_device)

        missing = async_client.get_missing_sessions(TEST_ROOM_ID)
        assert ALICE_ID in missing
        assert ALICE_DEVICE_ID in missing[ALICE_ID]

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=abc123",
            status=200,
            payload=self.keys_claim_dict(alice_client)
        )

        response = await async_client.keys_claim(missing)

        assert isinstance(response, KeysClaimResponse)
        assert not async_client.get_missing_sessions(TEST_ROOM_ID)
        assert async_client.olm.session_store.get(alice_device.curve25519)

    async def test_session_sharing(self, alice_client, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        await async_client.receive_response(self.encryption_sync_response)

        alice_client.load_store()
        alice_device = OlmDevice(
            ALICE_ID,
            ALICE_DEVICE_ID,
            alice_client.olm.account.identity_keys
        )

        async_client.device_store.add(alice_device)
        async_client.verify_device(alice_device)

        missing = async_client.get_missing_sessions(TEST_ROOM_ID)
        assert ALICE_ID in missing
        assert ALICE_DEVICE_ID in missing[ALICE_ID]

        to_share = alice_client.olm.share_keys()

        one_time_key = list(to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                ALICE_ID: {
                    ALICE_DEVICE_ID: {one_time_key[0]: one_time_key[1]},
                },
            },
            "failures": {},
        }

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=abc123",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(
            "https://example.org/_matrix/client/r0/sendToDevice/m.room.encrypted/1?access_token=abc123",
            status=200,
            payload={}
        )

        with pytest.raises(KeyError):
            session = async_client.olm.outbound_group_sessions[TEST_ROOM_ID]

        response = await async_client.share_group_session(TEST_ROOM_ID, "1")

        session = async_client.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert session.shared

        assert isinstance(response, ShareGroupSessionResponse)
        assert not async_client.get_missing_sessions(TEST_ROOM_ID)
        assert async_client.olm.session_store.get(alice_device.curve25519)

    async def test_joined_members(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        await async_client.receive_response(self.encryption_sync_response)
        aioresponse.get(
            "https://example.org/_matrix/client/r0/rooms/{}/"
            "joined_members?access_token=abc123".format(TEST_ROOM_ID),
            status=200,
            payload=self.joined_members_response
        )

        room = async_client.rooms[TEST_ROOM_ID]
        assert not room.members_synced

        response = await async_client.joined_members(TEST_ROOM_ID)

        assert isinstance(response, JoinedMembersResponse)
        assert room.members_synced

    async def test_joined_rooms(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        aioresponse.get(
            "https://example.org/_matrix/client/r0/joined_rooms?access_token=abc123",
            status=200,
            payload=self.joined_rooms_response
        )

        response = await async_client.joined_rooms()

        assert isinstance(response, JoinedRoomsResponse)

    async def test_session_sharing(self, alice_client, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        await async_client.receive_response(self.encryption_sync_response)

        alice_client.load_store()

        aioresponse.put(
            "https://example.org/_matrix/client/r0/sendToDevice/m.room_key_request/1?access_token=abc123",
            status=200,
            payload={}
        )

        event = MegolmEvent.from_dict(
            self._load_response("tests/data/events/megolm.json")
        )

        await async_client.request_room_key(event, "1")

        assert ("X3lUlvLELLYxeTx4yOVu6UDpasGEVO0Jbu+QFnm0cKQ" in
                async_client.outgoing_key_requests)

    async def test_key_exports(self, async_client, tempdir):
        file = path.join(tempdir, "keys_file")

        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        async_client.olm.create_outbound_group_session(TEST_ROOM_ID)

        out_session = async_client.olm.outbound_group_sessions[TEST_ROOM_ID]

        assert async_client.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            async_client.olm.account.identity_keys["curve25519"],
            out_session.id
        )
        await async_client.export_keys(file, "pass")

        alice_client = AsyncClient(
            "https://example.org",
            "alice",
            ALICE_DEVICE_ID,
            tempdir
        )

        alice_client.user_id = ALICE_ID
        alice_client.load_store()

        await alice_client.import_keys(file, "pass")

        imported_session = alice_client.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            async_client.olm.account.identity_keys["curve25519"],
            out_session.id
        )

        assert imported_session.id == out_session.id

    async def test_room_create(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/createRoom"
            "?access_token=abc123",
            status=200,
            payload=self.room_id_response(TEST_ROOM_ID),
        )

        resp = await async_client.room_create(
            visibility=RoomVisibility.public,
            alias="foo",
            name="bar",
            topic="Foos and bars",
            room_version="5",
            preset=RoomPreset.trusted_private_chat,
            invite={ALICE_ID},
            initial_state=[],
            power_level_override={},
        )
        assert isinstance(resp, RoomCreateResponse)
        assert resp.room_id == TEST_ROOM_ID

    async def test_join(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/join/{}"
            "?access_token=abc123".format(
                TEST_ROOM_ID
            ),
            status=200,
            payload=self.room_id_response(TEST_ROOM_ID),
        )

        resp = await async_client.join(TEST_ROOM_ID)
        assert isinstance(resp, JoinResponse)
        assert resp.room_id == TEST_ROOM_ID

    async def test_room_invite(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/rooms/{}/invite"
            "?access_token=abc123".format(TEST_ROOM_ID),
            status=200,
            payload={},
        )

        resp = await async_client.room_invite(TEST_ROOM_ID, ALICE_ID)
        assert isinstance(resp, RoomInviteResponse)

    async def test_room_leave(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/rooms/{}/leave"
            "?access_token=abc123".format(
                TEST_ROOM_ID
            ),
            status=200,
            payload={}
        )
        resp = await async_client.room_leave(TEST_ROOM_ID)
        assert isinstance(resp, RoomLeaveResponse)

    async def test_room_forget(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in
        await async_client.receive_response(self.encryption_sync_response)

        room_id = next(iter(async_client.rooms))

        aioresponse.post(
            "https://example.org/_matrix/client/r0/rooms/{}/forget"
            "?access_token=abc123".format(
                room_id
            ),
            status=200,
            payload={}
        )
        resp = await async_client.room_forget(room_id)
        assert isinstance(resp, RoomForgetResponse)
        assert room_id not in async_client.rooms

    async def test_room_redact(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in
        await async_client.receive_response(self.encryption_sync_response)

        room_id  = next(iter(async_client.rooms))
        event_id = "$15163622445EBvZJ:localhost"
        tx_id    = uuid4()
        reason   = "for no reason"

        aioresponse.put(
            "https://example.org/_matrix/client/r0/rooms/{}/redact/{}/{}"
            "?access_token=abc123".format(
                room_id, event_id, tx_id
            ),
            status=200,
            payload={"event_id": "$90813622447EBvZJ:localhost"},
        )
        resp = await async_client.room_redact(room_id, event_id, reason, tx_id)
        assert isinstance(resp, RoomRedactResponse)

    async def test_context(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in
        event_id = "$15163622445EBvZJ:localhost"

        await async_client.receive_response(self.encryption_sync_response)
        aioresponse.get(
            "https://example.org/_matrix/client/r0/rooms/{}/"
            "context/{}?access_token=abc123".format(
                TEST_ROOM_ID,
                event_id
            ),
            status=200,
            payload=self.context_response
        )

        response = await async_client.room_context(TEST_ROOM_ID, event_id)

        assert isinstance(response, RoomContextResponse)

    async def test_room_messages(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        await async_client.receive_response(self.encryption_sync_response)
        aioresponse.get(
            "https://example.org/_matrix/client/r0/rooms/{}/"
            "messages?access_token=abc123"
            "&dir=b&from=start_token&limit=10".format(
                TEST_ROOM_ID
            ),
            status=200,
            payload=self.messages_response
        )

        response = await async_client.room_messages(TEST_ROOM_ID, "start_token")

        assert isinstance(response, RoomMessagesResponse)

    async def test_room_typing(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in
        await async_client.receive_response(self.encryption_sync_response)

        room_id = list(async_client.rooms.keys())[0]

        aioresponse.put(
            "https://example.org/_matrix/client/r0/rooms/{}/typing/{}"
            "?access_token=abc123".format(
                room_id,
                async_client.user_id
            ),
            status=200,
            payload={}
        )
        resp = await async_client.room_typing(room_id, typing_state=True)
        assert isinstance(resp, RoomTypingResponse)

    async def test_content_repository_config(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response),
        )
        assert async_client.logged_in

        aioresponse.get(
            "https://example.org/_matrix/media/r0/config?access_token=abc123",
            status  = 200,
            payload = {"m.upload.size": 1024},
        )

        response = await async_client.content_repository_config()
        assert isinstance(response, ContentRepositoryConfigResponse)
        assert response.upload_size == 1024

    async def test_upload(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response),
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/media/r0/upload"
            "?access_token=abc123&filename=test.png",
            status=200,
            payload=self.upload_response,
            repeat=True,
        )

        path     = Path("tests/data/file_response")
        filesize = path.stat().st_size
        monitor  = TransferMonitor(filesize)

        resp, decryption_info = await async_client.upload(
            lambda *_: path, "image/png", "test.png", monitor=monitor,
        )
        assert isinstance(resp, UploadResponse)
        assert decryption_info is None

        # aioresponse doesn't do anything with the data_generator() in
        # upload(), so the monitor isn't updated.
        monitor.cancel = True
        self._wait_monitor_thread_exited(monitor)

    async def test_encrypted_upload(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response),
        )
        assert async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/media/r0/upload"
            "?access_token=abc123&filename=test.png",
            status  = 429,
            payload = self.limit_exceeded_error_response
        )

        aioresponse.post(
            "https://example.org/_matrix/media/r0/upload"
            "?access_token=abc123&filename=test.png",
            status  = 200,
            payload = self.upload_response,
            repeat  = True,
        )

        path    = Path("tests/data/file_response")
        monitor = TransferMonitor(path.stat().st_size)

        async with aiofiles.open(path, "rb") as file:
            resp, decryption_info = await async_client.upload(
                lambda *_: file,
                "image/png",
                "test.png",
                encrypt = True,
                monitor = monitor,
            )

        assert isinstance(resp, UploadResponse)
        assert isinstance(decryption_info, dict)

        # aioresponse doesn't do anything with the data_generator() in
        # upload(), so the decryption dict doesn't get updated and
        # we can't test wether it works as intended here.
        # Ditto for the monitor stats.

    async def test_traceconfig_callbacks(self):
        monitor = TransferMonitor(1)

        class Context:
            def __init__(self):
                self.trace_request_ctx = monitor

        session = ClientSession()
        context = Context()
        params  = TraceRequestChunkSentParams(chunk=b"x")

        await on_request_chunk_sent(session, context, params)
        assert monitor.transferred == 1
        self._verify_monitor_state_for_finished_transfer(monitor, 1)

    async def test_plain_data_generator(self, async_client):
        original_data   = [b"123", b"456", b"789", b"0"]
        data_size       = len(b"".join(original_data))
        monitor         = TransferMonitor(
            data_size,
            # Ensure the loop has time to land on the pause code
            _update_loop_sleep_time = 0.1,
        )

        gen  = async_client._plain_data_generator(original_data, monitor)
        data = []

        assert not monitor.pause
        data.append(await gen.__anext__())

        # Pausing and resuming

        async def unpause(speed_when_paused):
            await asyncio.sleep(0.5)
            monitor.pause = False
            assert speed_when_paused == monitor.speed

        paused_at         = time.time()
        monitor.pause     = True
        speed_when_paused = monitor.average_speed
        asyncio.ensure_future(unpause(speed_when_paused))
        data.append(await asyncio.wait_for(gen.__anext__(), 5))

        assert time.time() - paused_at >= 0.5

        # Cancelling and restarting

        monitor.cancel = True

        with pytest.raises(TransferCancelledError):
            await gen.__anext__()

        monitor.transferred += len(b"".join(data))
        assert monitor.transferred == len(b"".join(data))
        self._wait_monitor_thread_exited(monitor)

        left      = original_data[len(data):]
        left_size = len(b"".join(left))
        monitor   = TransferMonitor(left_size)
        gen       = async_client._plain_data_generator(left, monitor)

        # Finish and integrity checks

        data += [chunk async for chunk in gen]

        assert data == original_data
        monitor.transferred = monitor.total_size
        self._verify_monitor_state_for_finished_transfer(monitor, left_size)

    async def test_encrypted_data_generator(self, async_client):
        original_data   = b"x" * 4096 * 4
        data_size       = len(original_data)
        monitor         = TransferMonitor(data_size)
        decryption_dict = {}

        gen = async_client._encrypted_data_generator(
            original_data, decryption_dict, monitor,
        )
        encrypted_data = b""

        # Pausing and resuming

        assert not monitor.pause
        encrypted_data += await gen.__anext__()

        async def unpause():
            await asyncio.sleep(0.5)
            monitor.pause = False

        paused_at     = time.time()
        monitor.pause = True
        asyncio.ensure_future(unpause())
        encrypted_data += await asyncio.wait_for(gen.__anext__(), 5)

        assert time.time() - paused_at >= 0.5

        # Cancelling

        monitor.cancel = True

        with pytest.raises(TransferCancelledError):
            await gen.__anext__()

        monitor.transferred += len(encrypted_data)
        assert monitor.transferred == len(encrypted_data)
        self._wait_monitor_thread_exited(monitor)

        # Restart from scratch (avoid encrypted data SHA mismatch)

        decryption_dict = {}
        monitor         = TransferMonitor(data_size)
        gen             = async_client._encrypted_data_generator(
            original_data, decryption_dict, monitor,
        )

        # Finish and integrity checks

        encrypted_data = b"".join([chunk async for chunk in gen])

        assert encrypted_data
        assert "key" in decryption_dict
        assert "hashes" in decryption_dict
        assert "iv" in decryption_dict

        decrypted_data = decrypt_attachment(
            encrypted_data,
            decryption_dict["key"]["k"],
            decryption_dict["hashes"]["sha256"],
            decryption_dict["iv"],
        )

        assert decrypted_data == original_data
        monitor.transferred = monitor.total_size
        self._verify_monitor_state_for_finished_transfer(monitor, data_size)

    def test_transfer_monitor_callbacks(self):
        called = {"transferred": (0, 0), "speed_changed": 0}

        def on_transferred(transferred: int):
            called["transferred"] = (called["transferred"][0] + 1, transferred)

        def on_speed_changed(speed: float):
            called["speed_changed"] += 1

        monitor = TransferMonitor(100, on_transferred, on_speed_changed)
        monitor.transferred += 50

        slept = 0

        while not called["transferred"] or not called["speed_changed"]:
            time.sleep(0.1)
            slept += 0.1

            if slept >= 1:
                raise RuntimeError("1+ callback not called after 1s", called)

        assert called["transferred"] == (1, 50)
        assert called["speed_changed"] == 1

        monitor.transferred += 50
        self._verify_monitor_state_for_finished_transfer(monitor, 100)

    def test_transfer_monitor_bad_remaining_time(self):
        monitor = TransferMonitor(100)
        assert monitor.average_speed == 0.0
        assert monitor.remaining_time is None

        monitor.total_size = math.inf
        assert monitor.remaining_time is None

    @staticmethod
    def _wait_monitor_thread_exited(monitor):
        for _ in range(100):
            if not monitor._updater.is_alive():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("monitor._updater still alive after 10s")

    def _verify_monitor_state_for_finished_transfer(self, monitor, data_size):
        self._wait_monitor_thread_exited(monitor)
        assert monitor.total_size == data_size
        assert monitor.start_time and monitor.end_time
        assert monitor.average_speed > 0
        assert monitor.transferred == data_size
        assert monitor.percent_done == 100
        assert monitor.remaining == 0
        assert monitor.spent_time.microseconds > 0
        assert monitor.remaining_time.microseconds == 0
        assert monitor.done is True

    async def test_download(self, async_client, aioresponse):
        server_name = "example.org"
        media_id = "ascERGshawAWawugaAcauga"
        filename = "example&.png"  # has unsafe character to test % encoding

        aioresponse.get(
            "https://example.org/_matrix/media/r0/download/{}/{}"
            "?allow_remote=true".format(
                server_name,
                media_id,
            ),
            status=200,
            content_type="image/png",
            body=self.file_response,
        )
        resp = await async_client.download(server_name, media_id)
        assert isinstance(resp, DownloadResponse)
        assert resp.body == self.file_response
        assert resp.filename is None

        aioresponse.get(
            "https://example.org/_matrix/media/r0/download/{}/{}/{}"
            "?allow_remote=true".format(
                server_name,
                media_id,
                quote(filename),
            ),
            status=200,
            content_type="image/png",
            headers = {
                "content-disposition": 'inline; filename="{}"'.format(filename)
            },
            body=self.file_response,
        )
        resp = await async_client.download(server_name, media_id, filename)
        assert isinstance(resp, DownloadResponse)
        assert resp.body == self.file_response
        assert resp.filename == filename

        aioresponse.get(
            "https://example.org/_matrix/media/r0/download/{}/{}"
            "?allow_remote=true".format(
                server_name,
                media_id,
            ),
            status=429,
            content_type="application/json",
            body = b'{"errcode": "M_LIMIT_EXCEEDED"}',
        )
        resp = await async_client.download(server_name, media_id)
        assert isinstance(resp, DownloadError)

    async def test_thumbnail(self, async_client, aioresponse):
        server_name = "example.org"
        media_id = "ascERGshawAWawugaAcauga"
        width = 32
        height = 32
        method = ResizingMethod.crop

        aioresponse.get(
            "https://example.org/_matrix/media/r0/thumbnail/{}/{}"
            "?width={}&height={}&method={}&allow_remote=true".format(
                server_name,
                media_id,
                width,
                height,
                method.value,
            ),
            status=200,
            content_type="image/png",
            body=self.file_response,
        )
        resp = await async_client.thumbnail(
            server_name, media_id, width, height, method
        )
        assert isinstance(resp, ThumbnailResponse)
        assert resp.body == self.file_response

        aioresponse.get(
            "https://example.org/_matrix/media/r0/thumbnail/{}/{}"
            "?width={}&height={}&method={}&allow_remote=true".format(
                server_name,
                media_id,
                width,
                height,
                method.value,
            ),
            status=429,
            content_type="application/json",
            body = b'{"errcode": "M_LIMIT_EXCEEDED"}',
        )
        resp = await async_client.thumbnail(
            server_name, media_id, width, height, method
        )
        assert isinstance(resp, ThumbnailError)


    async def test_event_callback(self, async_client):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        class CallbackException(Exception):
            pass

        async def cb(_, event):
            if isinstance(event, RoomMemberEvent):
                raise CallbackException()

        async_client.add_event_callback(
            cb,
            (RoomMemberEvent, RoomEncryptionEvent)
        )

        with pytest.raises(CallbackException):
            await async_client.receive_response(self.encryption_sync_response)

    async def test_get_profile(self, async_client, aioresponse):
        base_url = "https://example.org/_matrix/client/r0"
        name = faker.name()
        avatar = faker.avatar_url().replace("#auto", "")

        aioresponse.get(
            "{}/profile/{}".format(base_url, async_client.user_id),
            status=200,
            payload=self.get_profile_response(name, avatar)
        )
        resp = await async_client.get_profile()
        assert isinstance(resp, ProfileGetResponse)
        assert resp.displayname == name
        assert resp.avatar_url.replace("#auto", "") == avatar

    async def test_devices(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        base_url = "https://example.org/_matrix/client/r0"

        delete_auth = {
            "flows": [{"stages": ["m.login.password"]}],
            "params": {},
            "session": "DBVNTKnPYYEVIvazoJwLqsNJ"
        }

        devices = {
            "devices": [
                {
                    "device_id": "ADJOYJBBHJ",
                    "display_name": None,
                    "last_seen_ip": "-",
                    "last_seen_ts": 1573294480287,
                    "user_id": "@example:localhost"
                }
            ]
        }

        aioresponse.post(f"{base_url}/delete_devices?access_token=abc123",
                         status=401, payload=delete_auth)
        aioresponse.post(f"{base_url}/delete_devices?access_token=abc123",
                         status=200, payload={})
        aioresponse.get(f"{base_url}/devices?access_token=abc123", status=200,
                        payload=devices)

        resp = await async_client.devices()
        assert isinstance(resp, DevicesResponse)
        assert len(resp.devices) == 1

        devices = [resp.devices[0].id]

        resp = await async_client.delete_devices(devices)
        assert isinstance(resp, DeleteDevicesAuthResponse)
        resp = await async_client.delete_devices(devices)
        assert isinstance(resp, DeleteDevicesResponse)

    async def test_get_set_displayname(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"

        aioresponse.get(
            "{}/profile/{}/displayname".format(base_url, async_client.user_id),
            status=200,
            payload=self.get_displayname_response(None)
        )
        resp = await async_client.get_displayname()
        assert isinstance(resp, ProfileGetDisplayNameResponse)
        assert not resp.displayname

        aioresponse.put(
            "{}/profile/{}/displayname?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
            status=200,
            payload={}
        )
        new_name = faker.name()
        resp2 = await async_client.set_displayname(new_name)
        assert isinstance(resp2, ProfileSetDisplayNameResponse)

        aioresponse.get(
            "{}/profile/{}/displayname".format(base_url, async_client.user_id),
            status=200,
            payload=self.get_displayname_response(new_name)
        )
        resp3 = await async_client.get_displayname()
        assert isinstance(resp3, ProfileGetDisplayNameResponse)
        assert resp3.displayname == new_name

    async def test_get_set_avatar(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"

        aioresponse.get(
            "{}/profile/{}/avatar_url".format(base_url, async_client.user_id),
            status=200,
            payload=self.get_avatar_response(None)
        )
        resp = await async_client.get_avatar()
        assert isinstance(resp, ProfileGetAvatarResponse)
        assert not resp.avatar_url

        aioresponse.put(
            "{}/profile/{}/avatar_url?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
            status=200,
            payload={}
        )
        new_avatar = faker.avatar_url().replace("#auto", "")
        resp2 = await async_client.set_avatar(new_avatar)
        assert isinstance(resp2, ProfileSetAvatarResponse)

        aioresponse.get(
            "{}/profile/{}/avatar_url".format(base_url, async_client.user_id),
            status=200,
            payload=self.get_avatar_response(new_avatar)
        )
        resp3 = await async_client.get_avatar()
        assert isinstance(resp3, ProfileGetAvatarResponse)
        assert resp3.avatar_url.replace("#auto", "") == new_avatar

    async def test_room_resolve_alias(self, async_client, aioresponse):
        aioresponse.get(
                "https://example.org/_matrix/client/r0/directory/room/%23test%3Aexample.org",
            status=200,
            payload=self.room_resolve_alias_response
        )

        resp = await async_client.room_resolve_alias("#test:example.org")

        assert isinstance(resp, RoomResolveAliasResponse)

    async def test_limit_exceeded(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=429,
            payload=self.limit_exceeded_error_response
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        got_error = []

        async def on_error(resp):
            assert isinstance(resp, ErrorResponse)
            expected = self.limit_exceeded_error_response["retry_after_ms"]
            assert resp.retry_after_ms == expected

            got_error.append(True)

        async_client.add_response_callback(on_error, ErrorResponse)

        resp = await async_client.login("wordpass")
        assert got_error == [True]
        assert isinstance(resp, LoginResponse)
        assert async_client.logged_in

    async def test_max_limit_exceeded(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=429,
            payload=self.limit_exceeded_error_response,
            repeat=True
        )

        async_client.config = AsyncClientConfig(max_limit_exceeded=2)

        got_error = []
        async def on_error(_):
            got_error.append(True)

        async_client.add_response_callback(on_error, ErrorResponse)

        resp = await async_client.login("wordpass")
        assert got_error == [True, True]
        assert isinstance(resp, ErrorResponse)
        assert resp.retry_after_ms
        assert not async_client.logged_in

    async def test_timeout(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response,
            timeout=True
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )

        async_client.config = AsyncClientConfig(max_timeouts=3)

        resp = await async_client.login("wordpass")
        assert isinstance(resp, LoginResponse)
        assert async_client.access_token
        assert async_client.logged_in

    async def test_max_timeouts(self, async_client, aioresponse):
        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response,
            timeout=True,
            repeat=True
        )

        async_client.config = AsyncClientConfig(max_timeouts=3)

        try:
            resp = await async_client.login("wordpass")
        except asyncio.TimeoutError:
            return

        raise RuntimeError("Did not get asyncio.TimeoutError")

    async def test_exponential_backoff(self, async_client):
        async_client.config = AsyncClientConfig(
            backoff_factor = 0.2,
            max_timeout_retry_wait_time = 30
        )

        get_time = async_client.get_timeout_retry_wait_time
        times = [await get_time(retries) for retries in range(1, 12)]

        assert times == [0.0, 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6, 30, 30, 30]

    async def test_sync_forever(self, async_client, aioresponse, loop):
        sync_url = re.compile(
            r'^https://example\.org/_matrix/client/r0/sync\?access_token=.*'
        )

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_response,
        )

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.empty_sync,
            repeat=True
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/upload?access_token=abc123",
            status=200,
            payload=self.keys_upload_response,
            repeat=True
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response,
            repeat=True
        )

        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        assert async_client.should_upload_keys

        task = loop.create_task(async_client.sync_forever(loop_sleep_time=100))

        await async_client.synced.wait()
        await async_client.synced.wait()

        assert not async_client.should_upload_keys

        task.cancel()
        await task

    async def test_session_unwedging(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9]\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        response = await bob.share_group_session(TEST_ROOM_ID, "1", True)
        assert isinstance(response, ShareGroupSessionResponse)

        # Check that the group session is indeed marked as shared.
        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob)
            )
        )

        # Run a sync for Alice, the sync will now contain the to-device message
        # containing the group session.
        await alice.sync()

        # Check that an Olm session was created.
        session = alice.olm.session_store.get(bob_device.curve25519)
        assert session

        # Let us pickle our session with bob here so we can later unpickle it
        # and wedge our session.
        alice_pickle = session.pickle("")

        # Check that we successfully received the group session as well.
        alice_group_session = alice.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            bob_device.curve25519,
            group_session.id
        )
        assert alice_group_session.id == group_session.id

        # Now let's share a session from alice to bob
        response = await alice.share_group_session(TEST_ROOM_ID, "1", True)
        assert isinstance(response, ShareGroupSessionResponse)

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice)
            )
        )

        group_session = alice.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared

        # Bob syncs and receives a the group session.
        await bob.sync()
        bob_group_session = bob.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            alice_device.curve25519,
            group_session.id
        )
        assert bob_group_session.id == group_session.id

        to_device_for_bob = None

        # Let us wedge the session now
        session = alice.olm.session_store.get(bob_device.curve25519)
        alice.olm.session_store[bob_device.curve25519][0] = (
            Session.from_pickle(alice_pickle, session.creation_time, "",
                                session.use_time))

        # Invalidate the current outbound group session
        alice.invalidate_outbound_session(TEST_ROOM_ID)
        assert TEST_ROOM_ID not in alice.olm.outbound_group_sessions

        # Let us try to share a session again.
        response = await alice.share_group_session(TEST_ROOM_ID, "2", True)
        assert isinstance(response, ShareGroupSessionResponse)

        group_session = alice.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_bob

        # Bob syncs, gets a new Olm message.
        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice),
                "2"
            )
        )
        assert not bob.outgoing_to_device_messages
        assert not bob.should_claim_keys

        # Set the creation time to be older than an hour, otherwise we will not
        # be able to unwedge the session.
        alice_session = bob.olm.session_store.get(alice_device.curve25519)
        alice_session.creation_time = datetime.now() - timedelta(hours=2)

        await bob.sync()
        # Check that bob was unable to decrypt the new group session.
        bob_group_session = bob.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            alice_device.curve25519,
            group_session.id
        )
        assert not bob_group_session

        # Check that alice was marked as wedged.
        assert alice_device in bob.olm.wedged_devices

        # Bob now needs to create a new Olm session with Alice, to do so he
        # needs to claim new one-time keys for the wedged devices.

        # Make sure that we don't reuse the first key.
        alice_one_time = list(alice_to_share["one_time_keys"].items())[1]
        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        assert not bob.outgoing_to_device_messages

        assert bob.should_claim_keys

        await bob.keys_claim(bob.get_users_for_key_claiming())

        # Now that bob created a new session, there should be a to-device
        # message waiting to be sent out to Alice
        assert not bob.olm.wedged_devices
        assert bob.outgoing_to_device_messages

        to_device_for_alice = None

        # Let's send out that message.
        await bob.send_to_device_messages()

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob),
                "3"
            )
        )

        # Take out the wedged session
        assert len(alice.olm.session_store[bob_device.curve25519]) == 1
        wedged_session = alice.olm.session_store.get(bob_device.curve25519)

        await alice.sync()

        # Check that there are now two sessions with bob
        assert len(alice.olm.session_store[bob_device.curve25519]) == 2

        # Check that the preferred session isn't the wedged one.
        new_session = alice.olm.session_store.get(bob_device.curve25519)

        assert new_session != wedged_session
        assert new_session.use_time > wedged_session.use_time

    async def test_key_sharing(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room[\._][_a-z]+/[0-9a-fA-f-]*\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        response = await bob.share_group_session(TEST_ROOM_ID, "1", True)
        assert isinstance(response, ShareGroupSessionResponse)

        # Check that the group session is indeed marked as shared.
        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice
        to_device_for_alice = None
        to_device_for_bob = None

        # We deliberatly don't share the message with alice
        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.olm.group_encrypt(TEST_ROOM_ID, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM_ID
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_room_event(encrypted_message, "3")
        )

        response = await alice.sync()

        assert isinstance(response, SyncResponse)

        # Alice received the event but wasn't able to decrypt it.
        event = response.rooms.join[TEST_ROOM_ID].timeline.events[0]
        assert isinstance(event, MegolmEvent)
        assert not to_device_for_bob

        # Let us request the key from bob again.
        await alice.request_room_key(event)

        # Check that bob will receive a message.
        assert to_device_for_bob

        # The client doesn't for now know how to re-request keys from bob, so
        # modify the message here.
        to_device_for_bob = {
            "messages": {
                bob_device.user_id: {
                    bob_device.device_id: to_device_for_bob["messages"][alice_device.user_id]["*"]
                }
            }
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.room_key_request"),
                "4"
            )
        )

        assert not bob.outgoing_to_device_messages

        # Bob syncs and receives a message.
        await bob.sync()

        # The key is now queued up for alice.
        assert bob.outgoing_to_device_messages

        assert not to_device_for_alice
        # Let's send out that message.
        await bob.send_to_device_messages()
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob),
                "5"
            )
        )

        # Alice syncs and receives the forwarded key.
        await alice.sync()

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    async def test_sas_verification(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.(room|key)[a-z_\.]+/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.(room|key)[a-z_\.]+/[0-9a-fA-f-]*\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        with pytest.raises(OlmTrustError):
            response = await bob.share_group_session(TEST_ROOM_ID, "1")

        to_device_for_alice = None

        await bob.start_key_verification(alice_device)

        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob, "m.key.verification.start"),
                "4"
            )
        )
        assert not alice.key_verifications
        await alice.sync()
        assert alice.key_verifications

        assert not to_device_for_bob

        await alice.accept_key_verification(list(alice.key_verifications.keys())[0])

        assert to_device_for_bob

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.accept"),
                "5"
            )
        )

        to_device_for_alice = None

        assert not bob.outgoing_to_device_messages
        await bob.sync()
        assert bob.outgoing_to_device_messages

        await bob.send_to_device_messages()
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob, "m.key.verification.key"),
                "6"
            )
        )

        assert not bob.outgoing_to_device_messages
        await alice.sync()
        assert alice.outgoing_to_device_messages
        await alice.send_to_device_messages()

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.key"),
                "7"
            )
        )

        await bob.sync()

        alice_sas = list(alice.key_verifications.values())[0]
        bob_sas = list(bob.key_verifications.values())[0]

        assert alice_sas.get_emoji() == bob_sas.get_emoji()

        assert not alice_device.verified
        assert not bob_device.verified

        await alice.confirm_short_auth_string(alice_sas.transaction_id)

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.mac"),
                "8"
            )
        )

        await bob.sync()

        await bob.confirm_short_auth_string(bob_sas.transaction_id)

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob, "m.key.verification.mac"),
                "8"
            )
        )

        await alice.sync()

        assert alice_device.verified
        assert bob_device.verified

        await bob.share_group_session(TEST_ROOM_ID, "1")

        # Check that the group session is indeed marked as shared.
        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice
        to_device_for_alice = None
        to_device_for_bob = None

        # We deliberatly don't share the message with alice
        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.olm.group_encrypt(TEST_ROOM_ID, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM_ID
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_room_event(encrypted_message, "3")
        )

        response = await alice.sync()

        assert isinstance(response, SyncResponse)

        # Alice received the event but wasn't able to decrypt it.
        event = response.rooms.join[TEST_ROOM_ID].timeline.events[0]
        assert isinstance(event, MegolmEvent)
        assert not to_device_for_bob

        # Let us request the key from bob again.
        await alice.request_room_key(event)

        # Check that bob will receive a message.
        assert to_device_for_bob

        # The client doesn't for now know how to re-request keys from bob, so
        # modify the message here.
        to_device_for_bob = {
            "messages": {
                bob_device.user_id: {
                    bob_device.device_id: to_device_for_bob["messages"][alice_device.user_id]["*"]
                }
            }
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.room_key_request"),
                "4"
            )
        )

        assert not bob.outgoing_to_device_messages

        # Bob syncs and receives a message.
        await bob.sync()

        # The key is now queued up for alice.
        assert bob.outgoing_to_device_messages

        assert not to_device_for_alice
        # Let's send out that message.
        await bob.send_to_device_messages()
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob),
                "5"
            )
        )

        # Alice syncs and receives the forwarded key.
        await alice.sync()

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    async def test_key_sharing_callbacks(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        # Key sharing callbacks will only be called for our own users and if a
        # device isn't trusted. Change the clients user names here.
        bob.user_id = alice.user_id
        bob.olm.user_id = alice.user_id

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        def key_request_cb(event):
            bob.verify_device(alice_device)

            for key_share in bob.get_active_key_requests(
                event.sender,
                event.requesting_device_id
            ):
                bob.continue_key_share(key_share)

        bob.add_to_device_callback(key_request_cb, RoomKeyRequest)

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room[\._][_a-z]+/[0-9a-fA-f-]*\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        response = await bob.share_group_session(TEST_ROOM_ID, "1", True)
        assert isinstance(response, ShareGroupSessionResponse)

        # Check that the group session is indeed marked as shared.
        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice
        to_device_for_alice = None
        to_device_for_bob = None

        # We deliberatly don't share the message with alice
        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.olm.group_encrypt(TEST_ROOM_ID, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM_ID
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_room_event(encrypted_message, "3")
        )

        response = await alice.sync()

        assert isinstance(response, SyncResponse)

        # Alice received the event but wasn't able to decrypt it.
        event = response.rooms.join[TEST_ROOM_ID].timeline.events[0]
        assert isinstance(event, MegolmEvent)
        assert not to_device_for_bob

        # Let us request the key from bob again.
        await alice.request_room_key(event)

        # Check that bob will receive a message.
        assert to_device_for_bob

        # The client doesn't for now know how to re-request keys from bob, so
        # modify the message here.
        to_device_for_bob = {
            "messages": {
                bob_device.user_id: {
                    bob_device.device_id: to_device_for_bob["messages"][alice_device.user_id]["*"]
                }
            }
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.room_key_request"),
                "4"
            )
        )

        assert not bob.outgoing_to_device_messages

        # Bob syncs and receives a message.
        await bob.sync()

        # The key is now queued up for alice.
        assert bob.outgoing_to_device_messages

        assert not to_device_for_alice
        # Let's send out that message.
        await bob.send_to_device_messages()
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob),
                "5"
            )
        )

        # Alice syncs and receives the forwarded key.
        await alice.sync()

        # Alice tries to decrypt the previous event again.
        decrypted_event = alice.decrypt_event(event)
        assert isinstance(decrypted_event, RoomMessageText)
        assert decrypted_event.body == "It's a secret to everybody."

    async def test_key_invalidation(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.(room|key)[a-z_\.]+/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, payload={}, repeat=True)

        await bob.share_group_session(TEST_ROOM_ID, "1", True)
        assert TEST_ROOM_ID in bob.olm.outbound_group_sessions
        bob.unignore_device(alice_device)
        assert TEST_ROOM_ID not in bob.olm.outbound_group_sessions

        bob.verify_device(alice_device)
        await bob.share_group_session(TEST_ROOM_ID, "2")
        assert TEST_ROOM_ID in bob.olm.outbound_group_sessions
        bob.unverify_device(alice_device)
        assert TEST_ROOM_ID not in bob.olm.outbound_group_sessions

        bob.blacklist_device(alice_device)
        await bob.share_group_session(TEST_ROOM_ID, "3")
        assert TEST_ROOM_ID in bob.olm.outbound_group_sessions
        bob.unblacklist_device(alice_device)
        assert TEST_ROOM_ID not in bob.olm.outbound_group_sessions

        bob.ignore_device(alice_device)
        await bob.share_group_session(TEST_ROOM_ID, "3")
        assert TEST_ROOM_ID in bob.olm.outbound_group_sessions
        bob.verify_device(alice_device)
        assert TEST_ROOM_ID not in bob.olm.outbound_group_sessions

    async def test_key_sharing_cancellation(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        alice.user_id = bob.user_id
        alice.olm.user_id = bob.user_id

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room[\._][_a-z]+/[0-9a-fA-f-]*\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        response = await bob.share_group_session(TEST_ROOM_ID, "1", True)
        assert isinstance(response, ShareGroupSessionResponse)

        # Check that the group session is indeed marked as shared.
        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice
        to_device_for_alice = None
        to_device_for_bob = None

        # We deliberatly don't share the message with alice
        message = {
            "type": "m.room.message",
            "content": {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            }
        }
        encrypted_content = bob.olm.group_encrypt(TEST_ROOM_ID, message)

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": encrypted_content,
            "room_id": TEST_ROOM_ID
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_room_event(encrypted_message, "3")
        )

        bob.invalidate_outbound_session(TEST_ROOM_ID)
        assert TEST_ROOM_ID not in bob.olm.outbound_group_sessions

        response = await alice.sync()

        assert isinstance(response, SyncResponse)

        # Alice received the event but wasn't able to decrypt it.
        event = response.rooms.join[TEST_ROOM_ID].timeline.events[0]
        assert isinstance(event, MegolmEvent)
        assert not to_device_for_bob

        # Let us request the key from bob again.
        await alice.request_room_key(event)

        # Check that bob will receive a message.
        assert to_device_for_bob

        # The client doesn't for now know how to re-request keys from bob, so
        # modify the message here.
        to_device_for_bob = {
            "messages": {
                bob_device.user_id: {
                    bob_device.device_id: to_device_for_bob["messages"][alice_device.user_id]["*"]
                }
            }
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.room_key_request"),
                "4"
            )
        )

        assert not bob.outgoing_to_device_messages

        # Bob syncs and receives a message.
        await bob.sync()

        assert not bob.outgoing_to_device_messages
        assert bob.olm.key_request_from_untrusted

        key_share = bob.get_active_key_requests(alice.user_id, alice.device_id)
        bob.cancel_key_share(key_share[0])

        assert not bob.outgoing_to_device_messages
        assert not bob.olm.key_request_from_untrusted

    async def test_sas_verification_cancel(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.(room|key)[a-z_\.]+/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.(room|key)[a-z_\.]+/[0-9a-fA-f-]*\?access_token=alice_1234",
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        # Share a group session for the room we're sharing with Alice.
        # This implicitly claims one-time keys since we don't have an Olm
        # session with Alice
        with pytest.raises(OlmTrustError):
            response = await bob.share_group_session(TEST_ROOM_ID, "1")

        to_device_for_alice = None

        await bob.start_key_verification(alice_device)

        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob, "m.key.verification.start"),
                "4"
            )
        )
        assert not alice.key_verifications
        await alice.sync()
        assert alice.key_verifications

        assert not to_device_for_bob

        await alice.accept_key_verification(list(alice.key_verifications.keys())[0])

        assert to_device_for_bob

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.accept"),
                "5"
            )
        )

        to_device_for_alice = None

        assert not bob.outgoing_to_device_messages
        await bob.sync()
        assert bob.outgoing_to_device_messages

        await bob.send_to_device_messages()
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob, "m.key.verification.key"),
                "6"
            )
        )

        assert not bob.outgoing_to_device_messages
        await alice.sync()
        assert alice.outgoing_to_device_messages
        await alice.send_to_device_messages()

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.key"),
                "7"
            )
        )

        await bob.sync()

        alice_sas = list(alice.key_verifications.values())[0]
        bob_sas = list(bob.key_verifications.values())[0]

        assert alice_sas.get_emoji() == bob_sas.get_emoji()

        assert not alice_device.verified
        assert not bob_device.verified

        await alice.cancel_key_verification(alice_sas.transaction_id)

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_bob, bob, alice, "m.key.verification.cancel"),
                "8"
            )
        )

        await bob.sync()

        assert not alice_device.verified
        assert not bob_device.verified

        assert alice_sas.canceled
        assert bob_sas.canceled

    async def test_e2e_sending(self, async_client_pair, aioresponse, loop):
        alice, bob = async_client_pair

        assert alice.logged_in
        assert bob.logged_in

        await alice.receive_response(self.synce_response_for(alice.user_id, bob.user_id))
        await bob.receive_response(self.synce_response_for(bob.user_id, alice.user_id))

        cb_ran = False

        def alice_event_cb(room, event):
            nonlocal cb_ran
            cb_ran = True
            assert isinstance(event, RoomMessageText)
            assert event.body == "It's a secret to everybody."

        alice.add_event_callback(alice_event_cb, (RoomMessageText, MegolmEvent))

        alice_device = OlmDevice(
            alice.user_id,
            alice.device_id,
            alice.olm.account.identity_keys
        )
        bob_device = OlmDevice(
            bob.user_id,
            bob.device_id,
            bob.olm.account.identity_keys
        )

        alice.olm.device_store.add(bob_device)
        bob.olm.device_store.add(alice_device)

        alice_to_share = alice.olm.share_keys()
        alice_one_time = list(alice_to_share["one_time_keys"].items())[0]

        key_claim_dict = {
            "one_time_keys": {
                alice.user_id: {
                    alice.device_id: {alice_one_time[0]: alice_one_time[1]},
                },
            },
            "failures": {},
        }

        to_device_for_alice = None
        to_device_for_bob = None
        room_event_for_alice = None

        sync_url = re.compile(
            r"^https://example\.org/_matrix/client/r0/sync\?access_token=.*"
        )

        bob_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9a-fA-f-]*\?access_token=bob_1234",
        )

        alice_to_device_url = re.compile(
            r"https://example\.org/_matrix/client/r0/sendToDevice/m\.room.encrypted/[0-9]\?access_token=alice_1234",
        )

        bob_room_send_url = re.compile(
            r"https://example\.org/_matrix/client/r0/rooms/{}/send/m\.room\.encrypted/[0-9]\?access_token=bob_1234".format(TEST_ROOM_ID),
        )

        def alice_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_alice
            to_device_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        def bob_to_device_cb(url, data, **kwargs):
            nonlocal to_device_for_bob
            to_device_for_bob = json.loads(data)
            return CallbackResult(status=200, payload={})

        def alice_room_send_cb(url, data, **kwargs):
            nonlocal room_event_for_alice
            room_event_for_alice = json.loads(data)
            return CallbackResult(status=200, payload={})

        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/claim?access_token=bob_1234",
            status=200,
            payload=key_claim_dict
        )

        aioresponse.put(bob_to_device_url, callback=alice_to_device_cb,
                        repeat=True)
        aioresponse.put(alice_to_device_url, callback=bob_to_device_cb,
                        repeat=True)

        aioresponse.put(bob_room_send_url, callback=alice_room_send_cb,
                        repeat=True)

        session = alice.olm.session_store.get(bob_device.curve25519)
        assert not session

        await bob.room_send(
            TEST_ROOM_ID,
            "m.room.message",
            {
                "msgtype": "m.text",
                "body": "It's a secret to everybody."
            },
            "1",
            ignore_unverified_devices=True
        )

        group_session = bob.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert group_session.shared
        assert to_device_for_alice

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_to_device_events(
                self.olm_message_to_event(to_device_for_alice, alice, bob)
            )
        )

        # Run a sync for Alice, the sync will now contain the to-device message
        # containing the group session.
        await alice.sync()

        # Check that an Olm session was created.
        session = alice.olm.session_store.get(bob_device.curve25519)
        assert session

        # Check that we successfully received the group session as well.
        alice_group_session = alice.olm.inbound_group_store.get(
            TEST_ROOM_ID,
            bob_device.curve25519,
            group_session.id
        )
        assert alice_group_session.id == group_session.id

        encrypted_message = {
            "event_id": "!event_id",
            "type": "m.room.encrypted",
            "sender": bob.user_id,
            "origin_server_ts": int(time.time()),
            "content": room_event_for_alice,
            "room_id": TEST_ROOM_ID
        }

        aioresponse.get(
            sync_url,
            status=200,
            payload=self.sync_with_room_event(encrypted_message, "3")
        )

        response = await alice.sync()

        assert isinstance(response, SyncResponse)

        # Alice received the event but wasn't able to decrypt it.
        event = response.rooms.join[TEST_ROOM_ID].timeline.events[0]
        assert isinstance(event, RoomMessageText)

        assert event.body == "It's a secret to everybody."
        assert cb_ran

    async def test_connect_wrapper(self, async_client, aioresponse):
        domain = "https://example.org"

        aioresponse.post(
            f"{domain}/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        await async_client.login("wordpass")

        assert async_client.client_session

        conn = await connect_wrapper(
            self    = async_client.client_session.connector,
            req     = ClientRequest(method="GET", url=URL(domain)),
            traces  = [],
            timeout = ClientTimeout(),
        )

        # Using conn.transport.get_write_buffer_limits() directly raises
        # "AttributeError: _low_water", but the set... method works?
        ssl_transport = conn.transport._ssl_protocol._transport
        assert ssl_transport.get_write_buffer_limits()[1] == 16 * 1024
