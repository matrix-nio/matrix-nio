import json
import sys
from os import path

import pytest

from nio import (DeviceList, DeviceOneTimeKeyCount, GroupEncryptionError,
                 JoinedMembersResponse, KeysClaimResponse, KeysQueryResponse,
                 KeysUploadResponse, LocalProtocolError, LoginError,
                 LoginResponse, MegolmEvent, MembersSyncError, OlmTrustError,
                 RoomEncryptionEvent, RoomInfo, RoomMemberEvent, Rooms,
                 RoomSendResponse, RoomSummary, ShareGroupSessionResponse,
                 SyncResponse, Timeline)
from nio.crypto import OlmDevice

TEST_ROOM_ID = "!testroom:example.org"

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"

if sys.version_info >= (3, 5):
    import asyncio
    from nio import AsyncClient


@pytest.mark.skipif(sys.version_info < (3, 5), reason="Python 3 specific asyncio tests")
class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    @property
    def login_response(self):
        return self._load_response("tests/data/login_response.json")

    @property
    def keys_upload_response(self):
        return self._load_response("tests/data/keys_upload.json")

    @property
    def sync_response(self):
        return self._load_response("tests/data/sync.json")

    @property
    def keys_query_response(self):
        return self._load_response(
            "tests/data/keys_query.json")

    @property
    def joined_members_resopnse(self):
        return {
            "joined": {
                "@bar:example.com": {
                    "avatar_url": None,
                    "display_name": "Bar"
                },
                ALICE_ID: {
                    "avatar_url": None,
                    "display_name": "Alice"
                },
            }}

    @property
    def encryption_sync_response(self):
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

    def test_keys_query(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()
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

        loop.run_until_complete(async_client.login("wordpass"))
        assert not async_client.should_query_keys

        async_client.receive_response(self.encryption_sync_response)
        assert async_client.should_query_keys

        loop.run_until_complete(async_client.keys_query())
        assert not async_client.should_query_keys

    def test_message_sending(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()
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
            payload=self.joined_members_resopnse
        )
        aioresponse.post(
            "https://example.org/_matrix/client/r0/keys/query?access_token=abc123",
            status=200,
            payload=self.keys_query_response
        )


        loop.run_until_complete(async_client.login("wordpass"))

        async_client.receive_response(self.encryption_sync_response)

        response = loop.run_until_complete(
            async_client.joined_members(TEST_ROOM_ID)
        )

        async_client.olm.create_outbound_group_session(TEST_ROOM_ID)
        async_client.olm.outbound_group_sessions[TEST_ROOM_ID].shared = True

        response = loop.run_until_complete(
            async_client.room_send(
                TEST_ROOM_ID,
                "m.room.message",
                {"body": "hello"},
                "1"
            )
        )

        assert isinstance(response, RoomSendResponse)

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


    def test_key_claiming(self, alice_client, async_client, aioresponse):
        loop = asyncio.get_event_loop()
        async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        async_client.receive_response(self.encryption_sync_response)

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

        response = loop.run_until_complete(
            async_client.keys_claim(missing)
        )

        assert isinstance(response, KeysClaimResponse)
        assert not async_client.get_missing_sessions(TEST_ROOM_ID)
        assert async_client.olm.session_store.get(alice_device.curve25519)

    def test_session_sharing(self, alice_client, async_client, aioresponse):
        loop = asyncio.get_event_loop()
        async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        async_client.receive_response(self.encryption_sync_response)

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

        response = loop.run_until_complete(
            async_client.share_group_session(TEST_ROOM_ID, "1")
        )

        session = async_client.olm.outbound_group_sessions[TEST_ROOM_ID]
        assert session.shared

        assert isinstance(response, ShareGroupSessionResponse)
        assert not async_client.get_missing_sessions(TEST_ROOM_ID)
        assert async_client.olm.session_store.get(alice_device.curve25519)

    def test_joined_members(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()
        async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        async_client.receive_response(self.encryption_sync_response)
        aioresponse.get(
            "https://example.org/_matrix/client/r0/rooms/{}/"
            "joined_members?access_token=abc123".format(TEST_ROOM_ID),
            status=200,
            payload=self.joined_members_resopnse
        )

        room = async_client.rooms[TEST_ROOM_ID]
        assert not room.members_synced

        response = loop.run_until_complete(
            async_client.joined_members(TEST_ROOM_ID)
        )

        assert isinstance(response, JoinedMembersResponse)
        assert room.members_synced

    def test_session_sharing(self, alice_client, async_client, aioresponse):
        loop = asyncio.get_event_loop()
        async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        async_client.receive_response(self.encryption_sync_response)

        alice_client.load_store()

        aioresponse.put(
            "https://example.org/_matrix/client/r0/sendToDevice/m.room_key_request/1?access_token=abc123",
            status=200,
            payload={}
        )

        event = MegolmEvent(
            "1",
            ALICE_ID,
            1,
            "sender_key_123",
            ALICE_DEVICE_ID,
            "session_id_123",
            "secret",
            "m.megolm.v1.aes-sha2",
            TEST_ROOM_ID,
        )

        loop.run_until_complete(async_client.request_room_key(event, "1"))

        assert "session_id_123" in async_client.outgoing_key_requests

    def test_key_exports(self, async_client, tempdir):
        file = path.join(tempdir, "keys_file")

        async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )

        async_client.olm.create_outbound_group_session(TEST_ROOM_ID)

        out_session = async_client.olm.outbound_group_sessions[TEST_ROOM_ID]

        assert async_client.olm.inbound_group_store.get(
                TEST_ROOM_ID,
                async_client.olm.account.identity_keys["curve25519"],
                out_session.id
        )
        loop = asyncio.get_event_loop()
        loop.run_until_complete(async_client.export_keys(file, "pass"))

        alice_client = AsyncClient(
            "https://example.org",
            "alice",
            ALICE_DEVICE_ID,
            tempdir
        )

        alice_client.user_id = ALICE_ID
        alice_client.load_store()

        loop.run_until_complete(alice_client.import_keys(file, "pass"))

        imported_session = alice_client.olm.inbound_group_store.get(
                TEST_ROOM_ID,
                async_client.olm.account.identity_keys["curve25519"],
                out_session.id
        )

        assert imported_session.id == out_session.id
