import json
import sys
import re
from os import path

import pytest

from helpers import faker
from nio import (DeviceList, DeviceOneTimeKeyCount, ErrorResponse,
                 GroupEncryptionError,
                 JoinResponse,
                 JoinedMembersResponse, KeysClaimResponse, KeysQueryResponse,
                 KeysUploadResponse, LocalProtocolError, LoginError,
                 LoginResponse, MegolmEvent, MembersSyncError, OlmTrustError,
                 RoomContextResponse, RoomForgetResponse,
                 ProfileGetAvatarResponse,
                 ProfileGetDisplayNameResponse, ProfileGetResponse,
                 ProfileSetAvatarResponse, ProfileSetDisplayNameResponse,
                 RoomTypingResponse,
                 RoomEncryptionEvent, RoomInfo, RoomLeaveResponse,
                 RoomMemberEvent, RoomMessagesResponse, Rooms,
                 RoomSendResponse, RoomSummary, ShareGroupSessionResponse,
                 SyncResponse, ThumbnailResponse, Timeline)
from nio.api import ResizingMethod
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
    def _load_bytes(filename):
        with open(filename, "rb") as f:
            return f.read()

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
                    "join",
                    None,
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

    @property
    def limit_exceeded_error_response(self):
        return self._load_response(
            "tests/data/limit_exceeded_error.json")

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
            payload=self.joined_members_resopnse
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
            payload=self.joined_members_resopnse
        )

        room = async_client.rooms[TEST_ROOM_ID]
        assert not room.members_synced

        response = await async_client.joined_members(TEST_ROOM_ID)

        assert isinstance(response, JoinedMembersResponse)
        assert room.members_synced

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

        room_id = list(async_client.rooms.keys())[0]

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

    async def test_thumbnail(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        server_name = "example.org"
        media_id = "ascERGshawAWawugaAcauga"
        width = 32
        height = 32
        method = ResizingMethod.crop

        aioresponse.get(
            "https://example.org/_matrix/media/r0/thumbnail/{}/{}"
            "?access_token=abc123&width={}&height={}&method={}"
            "&allow_remote=true".format(
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
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"
        name = faker.name()
        avatar = faker.avatar_url().replace("#auto", "")

        aioresponse.get(
            "{}/profile/{}?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
            status=200,
            payload=self.get_profile_response(name, avatar)
        )
        resp = await async_client.get_profile()
        assert isinstance(resp, ProfileGetResponse)
        assert resp.displayname == name
        assert resp.avatar_url.replace("#auto", "") == avatar

    async def test_get_set_displayname(self, async_client, aioresponse):
        await async_client.receive_response(
            LoginResponse.from_dict(self.login_response)
        )
        assert async_client.logged_in

        base_url = "https://example.org/_matrix/client/r0"

        aioresponse.get(
            "{}/profile/{}/displayname?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
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
            "{}/profile/{}/displayname?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
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
            "{}/profile/{}/avatar_url?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
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
            "{}/profile/{}/avatar_url?access_token={}".format(
                base_url, async_client.user_id, async_client.access_token
            ),
            status=200,
            payload=self.get_avatar_response(new_avatar)
        )
        resp3 = await async_client.get_avatar()
        assert isinstance(resp3, ProfileGetAvatarResponse)
        assert resp3.avatar_url.replace("#auto", "") == new_avatar

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
