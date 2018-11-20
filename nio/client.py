# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import json
import pprint
from builtins import bytes, str, super
from enum import Enum, unique
from collections import deque, namedtuple
from typing import (
    Any,
    AnyStr,
    Deque,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
    NamedTuple
)
from uuid import UUID, uuid4

import h2
import h11
from logbook import Logger

from .api import Api, MessageDirection
from .exceptions import (
    LocalProtocolError,
    RemoteProtocolError,
    RemoteTransportError,
)
from .encryption import Olm
from .http import HttpRequest, Http2Request
from .cryptostore import OlmDevice
from .http import (
    Http2Connection,
    HttpConnection,
    TransportType,
    TransportResponse,
    TransportRequest
)
from .log import logger_group
from .responses import (
    JoinResponse,
    LoginResponse,
    Response,
    RoomInviteResponse,
    RoomKickResponse,
    RoomLeaveResponse,
    RoomPutStateResponse,
    RoomRedactResponse,
    RoomSendResponse,
    SyncResponse,
    SyncType,
    PartialSyncResponse,
    RoomMessagesResponse,
    KeysUploadResponse,
    KeysQueryResponse,
    ErrorResponse,
    ShareGroupSessionResponse,
    KeysClaimResponse,
    DevicesResponse,
    UpdateDeviceResponse,
    DeleteDevicesAuthResponse,
    DeleteDevicesResponse,
    JoinedMembersResponse,
    KeysUploadError
)

from .events import Event, BadEventType, RoomEncryptedEvent, MegolmEvent
from .rooms import MatrixInvitedRoom, MatrixRoom

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


logger = Logger("nio.client")
logger_group.add_logger(logger)


@unique
class RequestType(Enum):
    login = 0
    sync = 1
    room_send = 2
    room_put_state = 3
    room_redact = 4
    room_kick = 5
    room_invite = 6
    join = 7
    room_leave = 8
    room_messages = 9
    keys_upload = 10
    keys_query = 11
    keys_claim = 12
    share_group_session = 13
    devices = 14
    delete_devices = 15
    update_device = 16
    joined_members = 17


_RequestInfo = NamedTuple(
    "RequestInfo",
    [
        ("type", RequestType),
        ("extra_data", Optional[str])
    ]
)


class RequestInfo(_RequestInfo):
    def __new__(cls, type, extra_data=None):
        # type: (RequestType, Optional[str]) -> RequestInfo
        return super().__new__(cls, type, extra_data)


class Client(object):
    def __init__(
        self,
        user=None,  # type: Optional[str]
        device_id=None,  # type: Optional[str]
        session_dir="",  # type: Optional[str]
    ):
        # type: (...) -> None
        self.user = user
        self.device_id = device_id
        self.session_dir = session_dir
        self.olm = None  # type: Optional[Olm]

        self.user_id = ""
        self.access_token = ""
        self.next_batch = ""

        self.rooms = dict()  # type: Dict[str, MatrixRoom]
        self.invited_rooms = dict()  # type: Dict[str, MatrixRoom]

    def _load_olm(self):
        # TODO load the olm account and sessions from the session dir
        return False

    @property
    def logged_in(self):
        """A property that tracks the logged in status of the client.
        Returns True if the client is logged in to the server, False otherwise.
        """
        # type: () -> bool
        return True if self.access_token else False

    @property
    def olm_account_shared(self):
        """Check if the clients Olm account is shared with the server.
        Returns True if the Olm account is shared, False otherwise.
        """
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")

        return self.olm.account.shared

    @property
    def should_upload_keys(self):
        """Check if the client should upload encryption keys.
        Returns True if a keys need to be uploaded, false otherwise.
        """
        if not self.olm:
            return False

        return self.olm.should_upload_keys

    @property
    def should_query_keys(self):
        """Check if the client should make a key query call to the server.
        Returns True if a key query is necessary, false otherwise.
        """
        if not self.olm:
            return False

        return self.olm.should_query_keys

    def room_contains_unverified(self, room_id):
        """Check if a room contains unverified devices.
        Args:
            room_id (str): Room id of the room that should be checked.

        Returns True if the room contains unverified devices, false otherwise.
        Returns False if no Olm session is loaded or if the room isn't
        encrypted.
        """
        # type: (str) -> bool
        room = self.rooms[room_id]

        if not room.encrypted:
            return False

        if not self.olm:
            return False

        for user in room.users:
            if not self.olm.user_fully_verified(user):
                return True

        return False

    def invalidate_outbound_session(self, room_id):
        """Explicitely remove encryption keys for a room.
        Args:
            room_id (str): Room id for the room the encryption keys should be
                removed.
        """
        session = self.olm.outbound_group_sessions.pop(
            room_id,
            None
        )

        # There is no need to invalidate the session if it was never
        # shared, put it back where it was.
        if session and not session.shared:
            self.olm.outbound_group_sessions[room_id] = session

    def _invalidate_outbound_sessions(self, device):
        # type: (OlmDevice) -> None
        assert self.olm

        for room in self.rooms.values():
            if device.user_id in room.users:
                self.invalidate_outbound_session(room.room_id)

    def verify_device(self, device):
        """Mark a device as verified.
        A device needs to be either trusted or blacklisted to either share room
        encryption keys with it or not.
        This method adds the device to the trusted devices and enables sharing
        room encryption keys with it.

        Args:
            device (Device): The device which should be added to the trust
                list.
        Returns true if the device was verified, false if it was already
        verified.
        """
        # type: (OlmDevice) -> bool
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")

        changed = self.olm.verify_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    def unverify_device(self, device):
        """Unmark a device as verified.
        This method removes the device from the trusted devices and disables
        sharing room encryption keys with it. It also invalidates any
        encryption keys for rooms that the device takes part of.

        Args:
            device (Device): The device which should be added to the trust
                list.
        Returns true if the device was unverified, false if it was already
        unverified.
        """
        # type: (OlmDevice) -> bool
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")

        changed = self.olm.unverify_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    def blacklist_device(self, device):
        """Mark a device as blacklisted.
        Devices on the blacklist will not receive room encryption keys and
        therefore won't be able to decrypt messages coming from this client.
        Args:
            device (Device): The device which should be added to the
                blacklist.
        Returns true if the device was added, false if it was on the blacklist
        already.
        """
        # type: (OlmDevice) -> bool
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")
        changed = self.olm.blacklist_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    def unblacklist_device(self, device):
        """Unmark a device as blacklisted.
        Args:
            device (Device): The device which should be removed from the
                blacklist.
        Returns true if the device was removed, false if it wasn't on the
        blacklist and no removal happened.
        """
        # type: (OlmDevice) -> bool
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")
        return self.olm.unblacklist_device(device)

    def _handle_login(self, response):
        # type: (Union[LoginResponse, ErrorResponse]) -> None
        if isinstance(response, ErrorResponse):
            return

        self.access_token = response.access_token
        self.user_id = response.user_id
        self.device_id = response.device_id

        if self.session_dir:
            self.olm = Olm(self.user_id, self.device_id, self.session_dir)

    def _handle_sync(self, response):
        # type: (Union[SyncType, ErrorResponse]) -> None
        # We already recieved such a sync response, do nothing in that case.
        if self.next_batch == response.next_batch:
            return

        if isinstance(response, SyncResponse):
            self.next_batch = response.next_batch

        for to_device_event in response.to_device_events:
            if isinstance(to_device_event, RoomEncryptedEvent):
                if not self.olm:
                    continue
                self.olm.decrypt_event(to_device_event)

        for room_id, info in response.rooms.invite.items():
            if room_id not in self.invited_rooms:
                logger.info("New invited room {}".format(room_id))
                self.invited_rooms[room_id] = MatrixInvitedRoom(
                    room_id, self.user_id
                )

            room = self.invited_rooms[room_id]

            for event in info.invite_state:
                room.handle_event(event)

        for room_id, join_info in response.rooms.join.items():
            if room_id in self.invited_rooms:
                del self.invited_rooms[room_id]

            if room_id not in self.rooms:
                logger.info("New joined room {}".format(room_id))
                self.rooms[room_id] = MatrixRoom(room_id, self.user_id)

            room = self.rooms[room_id]

            for event in join_info.state:
                room.handle_event(event)

            decrypted_events = []  \
                # type: List[Tuple[int, Union[Event, BadEventType]]]

            for index, event in enumerate(join_info.timeline.events):
                if isinstance(event, MegolmEvent) and self.olm:
                    event.room_id = room_id
                    new_event = self.olm.decrypt_event(event)
                    if new_event:
                        event = new_event
                        decrypted_events.append((index, new_event))
                room.handle_event(event)

            # Replace the Megolm events with decrypted ones
            for decrypted_event in decrypted_events:
                index, event = decrypted_event
                join_info.timeline.events[index] = event

            for event in join_info.ephemeral:
                room.handle_ephemeral_event(event)

            if room.encrypted and self.olm is not None:
                self.olm.update_tracked_users(room)

        if self.olm:
            changed_users = set()
            self.olm.uploaded_key_count = (
                response.device_key_count.signed_curve25519)

            for user in response.device_list.changed:
                for room in self.rooms.values():
                    if not room.encrypted:
                        continue

                    if user in room.users:
                        changed_users.add(user)

            for user in response.device_list.left:
                for room in self.rooms.values():
                    if not room.encrypted:
                        continue

                    if user in room.users:
                        changed_users.add(user)

            self.olm.users_for_key_query.update(changed_users)

    def _handle_messages_response(self, response):
        decrypted_events = []

        for index, event in enumerate(response.chunk):
            if isinstance(event, MegolmEvent) and self.olm:
                new_event = self.olm.decrypt_event(event)
                if new_event:
                    decrypted_events.append((index, new_event))

        for decrypted_event in decrypted_events:
            index, event = decrypted_event
            response.chunk[index] = event

    def _handle_olm_response(self, response):
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")

        self.olm.handle_response(response)

        if isinstance(response, KeysQueryResponse):
            for user_id in response.changed:
                for room in self.rooms.values():
                    if room.encrypted and user_id in room.users:
                        self.invalidate_outbound_session(room.room_id)

    def _handle_joined_members(self, response):
        room = self.rooms[response.room_id]

        for member in response.members:
            room.add_member(member.user_id, member.display_name)

    def receive_response(self, response):
        """Receive a Matrix Response and change the client state accordingly.
        Some responses will get edited for the callers convenience e.g. sync
        responses that contain encrypted messages. The encrypted messages will
        be replaced by decrypted ones if decryption is possible.
        Args:
            response (Response): the response that we wish the client to handle
        """
        if isinstance(response, LoginResponse):
            self._handle_login(response)
        elif isinstance(response, (SyncResponse, PartialSyncResponse)):
            self._handle_sync(response)
        elif isinstance(response, RoomMessagesResponse):
            self._handle_messages_response(response)
        elif isinstance(response, KeysUploadResponse):
            self._handle_olm_response(response)
        elif isinstance(response, KeysQueryResponse):
            self._handle_olm_response(response)
        elif isinstance(response, KeysClaimResponse):
            self._handle_olm_response(response)
        elif isinstance(response, ShareGroupSessionResponse):
            self._handle_olm_response(response)
        elif isinstance(response, JoinedMembersResponse):
            self._handle_joined_members(response)
        else:
            pass


def connected(func):
    def wrapper(*args, **kwargs):
        self = args[0]
        if not self.connection:
            raise LocalProtocolError("Not connected.")
        return func(*args, **kwargs)
    return wrapper


def logged_in(func):
    def wrapper(*args, **kwargs):
        self = args[0]
        if not self.logged_in:
            raise LocalProtocolError("Not logged in.")
        return func(*args, **kwargs)
    return wrapper


class HttpClient(Client):
    def __init__(
        self,
        host,  # type: str
        user="",  # type: str
        device_id="",  # type: Optional[str]
        session_dir="",  # type: Optional[str]
    ):
        # type: (...) -> None
        self.host = host
        self.requests_made = {}  # type: Dict[UUID, RequestInfo]
        self.parse_queue = deque()  \
            # type: Deque[Tuple[RequestInfo, TransportResponse]]
        self.partial_sync = None  # type: Optional[PartialSyncResponse]

        self.connection = None \
            # type: Optional[Union[HttpConnection, Http2Connection]]

        super().__init__(user, device_id, session_dir)

    @connected
    def _send(self, request, request_info, uuid=None):
        # type: (TransportRequest, Optional[UUID]) -> Tuple[UUID, bytes]
        ret_uuid, data = self.connection.send(request, uuid)
        self.requests_made[ret_uuid] = request_info
        return ret_uuid, data

    def _build_request(self, api_response, timeout=0):
        def unpack_api_call(method, *rest):
            return method, rest

        method, api_data = unpack_api_call(*api_response)

        if isinstance(self.connection, HttpConnection):
            if method == "GET":
                path = api_data[0]
                return HttpRequest.get(self.host, path, timeout)
            elif method == "POST":
                path, data = api_data
                return HttpRequest.post(self.host, path, data, timeout)
            elif method == "PUT":
                path, data = api_data
                return HttpRequest.put(self.host, path, data, timeout)
        elif isinstance(self.connection, Http2Connection):
            if method == "GET":
                path = api_data[0]
                return Http2Request.get(self.host, path, timeout)
            elif method == "POST":
                path, data = api_data
                return Http2Request.post(self.host, path, data, timeout)
            elif method == "PUT":
                path, data = api_data
                return Http2Request.put(self.host, path, data, timeout)

        assert("Invalid connection type")

    @property
    def lag(self):
        # type: () -> float
        if not self.connection:
            return 0

        return self.connection.elapsed

    def connect(self, transport_type=TransportType.HTTP):
        # type: (Optional[TransportType]) -> bytes
        if transport_type == TransportType.HTTP:
            self.connection = HttpConnection()
        elif transport_type == TransportType.HTTP2:
            self.connection = Http2Connection()
        else:
            raise NotImplementedError

        return self.connection.connect()

    def _clear_queues(self):
        self.requests_made.clear()
        self.parse_queue.clear()

    @connected
    def disconnect(self):
        # type: () -> bytes
        data = self.connection.disconnect()
        self._clear_queues()
        self.connection = None
        return data

    @connected
    def data_to_send(self):
        # type: () -> bytes
        return self.connection.data_to_send()

    @connected
    def login(self, password, device_name=""):
        # type: (str, Optional[str]) -> Tuple[UUID, bytes]
        request = self._build_request(
            Api.login(
                self.user,
                password,
                device_name=device_name,
                device_id=self.device_id
            )
        )

        return self._send(request, RequestInfo(RequestType.login))

    @connected
    @logged_in
    def room_send(self, room_id, message_type, content, tx_id=None):
        # TODO this can fail if we're not synced
        if self.olm:
            room = self.rooms[room_id]

            if room.encrypted:
                content = self.olm.group_encrypt(
                    room_id,
                    {
                        "content": content,
                        "type": message_type
                    },
                )
                message_type = "m.room.encrypted"

        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.room_send(
                self.access_token,
                room_id,
                message_type,
                content,
                uuid
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.room_send, room_id),
            uuid
        )

    @connected
    @logged_in
    def room_put_state(self, room_id, event_type, body):
        request = self._build_request(
            Api.room_put_state(
                self.access_token,
                room_id,
                event_type,
                body
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.room_put_state, room_id)
        )

    @connected
    @logged_in
    def room_redact(self, room_id, event_id, reason=None, tx_id=None):
        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.room_redact(
                self.access_token,
                room_id,
                event_id,
                tx_id,
                reason=reason,
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.room_redact, room_id),
            uuid
        )

    @connected
    @logged_in
    def room_kick(self, room_id, user_id, reason=None):
        request = self._build_request(
            Api.room_kick(
                self.access_token,
                room_id,
                user_id,
                reason=reason
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.room_kick)
        )

    @connected
    @logged_in
    def room_invite(self, room_id, user_id):
        request = self._build_request(
            Api.room_invite(
                self.access_token,
                room_id,
                user_id
            )
        )

        return self._send(request, RequestInfo(RequestType.room_invite))

    @connected
    @logged_in
    def join(self, room_id):
        request = self._build_request(Api.join(self.access_token, room_id))
        return self._send(request, RequestInfo(RequestType.room_join))

    @connected
    @logged_in
    def room_leave(self, room_id):
        request = self._build_request(
            Api.room_leave(
                self.access_token,
                room_id
            )
        )
        return self._send(request, RequestInfo(RequestType.room_leave))

    @connected
    @logged_in
    def room_messages(
        self,
        room_id,
        start,
        end=None,
        direction=MessageDirection.back,
        limit=10
    ):
        request = self._build_request(
            Api.room_messages(
                self.access_token,
                room_id,
                start,
                end=end,
                direction=direction,
                limit=limit
            )
        )
        return self._send(request, RequestInfo(RequestType.room_messages))

    @connected
    @logged_in
    def keys_upload(self):
        keys_dict = self.olm.share_keys()

        logger.debug(pprint.pformat(keys_dict))

        request = self._build_request(
            Api.keys_upload(
                self.access_token,
                keys_dict
            )
        )
        return self._send(request, RequestInfo(RequestType.keys_upload))

    @connected
    @logged_in
    def keys_query(self, full=False):
        if not full:
            user_list = self.olm.users_for_key_query
        else:
            user_list = [
                user_id for room in self.rooms.values()
                if room.encrypted for user_id in room.users
            ]

        request = self._build_request(
            Api.keys_query(
                self.access_token,
                user_list
            )
        )
        return self._send(request, RequestInfo(RequestType.keys_query))

    @connected
    @logged_in
    def keys_claim(self, room_id):
        if not self.olm:
            raise LocalProtocolError("Olm session is not loaded")

        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError("No such room with id {}".format(room_id))

        if not room.encrypted:
            raise LocalProtocolError("Room with id {} is not encrypted".format(
                                     room_id))

        user_list = self.olm.get_missing_sessions(
            list(room.users.keys())
        )
        request = self._build_request(
            Api.keys_claim(
                self.access_token,
                user_list
            )
        )
        return self._send(
            request,
            RequestInfo(RequestType.keys_claim, room_id)
        )

    @connected
    @logged_in
    def share_group_session(
        self,
        room_id,
        ignore_missing_sessions=False,
        tx_id=None
    ):
        # type: (str, bool, str) -> Tuple[UUID, bytes]
        if not self.olm:
            raise LocalProtocolError("Olm session is not loaded")

        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError("No such room with id {}".format(room_id))

        if not room.encrypted:
            raise LocalProtocolError("Room with id {} is not encrypted".format(
                room_id))

        to_device_dict = self.olm.share_group_session(
            room_id,
            list(room.users.keys()),
            ignore_missing_sessions
        )

        uuid = str(tx_id) or uuid4()

        request = self._build_request(
            Api.to_device(
                self.access_token,
                "m.room.encrypted",
                to_device_dict,
                uuid
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.share_group_session, room_id)
        )

    @connected
    @logged_in
    def devices(self):
        # type: () -> Tuple[UUID, bytes]
        request = self._build_request(Api.devices(self.access_token))
        return self._send(request, RequestInfo(RequestType.devices))

    @connected
    @logged_in
    def update_device(self, device_id, content):
        # type: (str, Dict[str, str]) -> Tuple[UUID, bytes]
        request = self._build_request(
            Api.update_device(
                self.access_token,
                device_id,
                content
            )
        )

        return self._send(request, RequestInfo(RequestType.update_device))

    @connected
    @logged_in
    def delete_devices(self, devices, auth=None):
        # type: (List[str], Optional[Dict[str, str]]) -> Tuple[UUID, bytes]
        request = self._build_request(
            Api.delete_devices(
                self.access_token,
                devices,
                auth_dict=auth
            )
        )

        return self._send(request, RequestInfo(RequestType.delete_devices))

    @connected
    @logged_in
    def joined_members(self, room_id):
        # type: (str) -> Tuple[UUID, bytes]
        request = self._build_request(
            Api.joined_members(
                self.access_token,
                room_id
            )
        )

        return self._send(
            request,
            RequestInfo(RequestType.joined_members, room_id)
        )

    @connected
    @logged_in
    def sync(self, timeout=None, filter=None):
        # type: (Optional[int], Optional[Dict[Any, Any]]) -> Tuple[UUID, bytes]
        request = self._build_request(
            Api.sync(
                self.access_token,
                next_batch=self.next_batch,
                timeout=timeout,
                filter=filter
            ),
            timeout
        )

        return self._send(request, RequestInfo(RequestType.sync))

    @staticmethod
    def _create_response(request_info, transport_response, max_events=0):
        request_type = request_info.type
        try:
            parsed_dict = json.loads(transport_response.text, encoding="utf-8")
        except JSONDecodeError:
            parsed_dict = {}

        if request_type is RequestType.login:
            response = LoginResponse.from_dict(parsed_dict)
        elif request_type is RequestType.sync:
            response = SyncResponse.from_dict(parsed_dict, max_events)
        elif request_type is RequestType.room_send:
            response = RoomSendResponse.from_dict(
                parsed_dict,
                request_info.extra_data
            )
        elif request_type is RequestType.room_put_state:
            response = RoomPutStateResponse.from_dict(
                parsed_dict,
                request_info.extra_data
            )
        elif request_type is RequestType.room_redact:
            response = RoomRedactResponse.from_dict(
                parsed_dict,
                request_info.extra_data
            )
        elif request_type is RequestType.room_kick:
            response = RoomKickResponse.from_dict(parsed_dict)
        elif request_type is RequestType.room_invite:
            response = RoomInviteResponse.from_dict(parsed_dict)
        elif request_type is RequestType.join:
            response = JoinResponse.from_dict(parsed_dict)
        elif request_type is RequestType.room_leave:
            response = RoomLeaveResponse.from_dict(parsed_dict)
        elif request_type is RequestType.room_messages:
            response = RoomMessagesResponse.from_dict(parsed_dict)
        elif request_type is RequestType.keys_upload:
            response = KeysUploadResponse.from_dict(parsed_dict)
        elif request_type is RequestType.keys_query:
            response = KeysQueryResponse.from_dict(parsed_dict)
        elif request_type is RequestType.keys_claim:
            response = KeysClaimResponse.from_dict(parsed_dict)
        elif request_type is RequestType.share_group_session:
            response = ShareGroupSessionResponse.from_dict(
                parsed_dict,
                request_info.extra_data
            )
        elif request_type is RequestType.devices:
            response = DevicesResponse.from_dict(parsed_dict)
        elif request_type is RequestType.update_device:
            response = UpdateDeviceResponse.from_dict(parsed_dict)
        elif request_type is RequestType.joined_members:
            response = JoinedMembersResponse.from_dict(
                parsed_dict,
                request_info.extra_data
            )
        elif request_type is RequestType.delete_devices:
            if transport_response.status_code == 401:
                response = DeleteDevicesAuthResponse.from_dict(parsed_dict)
            else:
                response = DeleteDevicesResponse.from_dict(parsed_dict)

        assert response

        response.start_time = transport_response.send_time
        response.end_time = transport_response.receive_time
        response.timeout = transport_response.timeout
        response.status_code = transport_response.status_code
        response.uuid = transport_response.uuid

        return response

    def handle_key_upload_error(self, response):
        if response.status_code in [400, 500]:
            self.olm.mark_keys_as_published()
            self.olm.save_account()

    @connected
    def receive(self, data):
        # type: (bytes) -> None
        try:
            response = self.connection.receive(data)
        except (h11.RemoteProtocolError, h2.exceptions.ProtocolError) as e:
            raise RemoteTransportError(e)

        if response:
            try:
                request_info = self.requests_made.pop(response.uuid)
            except KeyError:
                logger.error("{}".format(pprint.pformat(self.requests_made)))
                raise

            if response.is_ok:
                logger.info(
                    "Received response of type: {}".format(request_info.type)
                )
            else:
                logger.info(
                    (
                        "Error with response of type type: {}, "
                        "error code {}"
                    ).format(request_info.type, response.status_code)
                )

            self.parse_queue.append((request_info, response))
        return

    def next_response(self, max_events=0):
        # type: (int) -> Optional[Union[TransportResponse, Response]]
        if not self.parse_queue and not self.partial_sync:
            return None

        if self.partial_sync:
            sync_response = self.partial_sync.next_part(max_events)
            self.receive_response(sync_response)

            if isinstance(sync_response, PartialSyncResponse):
                self.partial_sync = sync_response

            return sync_response

        request_info, transport_response = self.parse_queue.popleft()
        response = self._create_response(
            request_info,
            transport_response,
            max_events
        )

        if isinstance(response, KeysUploadError):
            self.handle_key_upload_error(response)

        self.receive_response(response)

        return response
