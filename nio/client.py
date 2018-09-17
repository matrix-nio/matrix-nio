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

from __future__ import unicode_literals

import json
import pprint
from builtins import bytes, str
from enum import Enum, unique
from collections import deque, namedtuple
from typing import Any, AnyStr, Deque, Dict, List, Optional, Tuple, Union
from uuid import UUID

import h2
import h11
from logbook import Logger

from .api import Http2Api, HttpApi, MessageDirection
from .exceptions import (
    LocalProtocolError,
    RemoteProtocolError,
    RemoteTransportError,
)
from .encryption import Olm
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
    SyncRepsponse,
    RoomMessagesResponse,
    KeysUploadResponse,
)

from .events import RoomEncryptedEvent, MegolmEvent
from .rooms import MatrixInvitedRoom, MatrixRoom

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


logger = Logger("nio.client")
logger_group.add_logger(logger)


TypedResponse = namedtuple("TypedResponse", ["type", "data", "uuid", "timing"])
TimingInfo = namedtuple("TimingInfo", ["start", "end"])
RequestInfo = namedtuple("RequestInfo", ["type", "timeout"])


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
        self.parse_queue = deque()  # type: Deque[TypedResponse]
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
        # type: () -> bool
        return True if self.access_token else False

    @property
    def olm_account_shared(self):
        if not self.olm:
            raise LocalProtocolError("Olm account isn't loaded")

        return self.olm.account.shared

    @property
    def should_upload_keys(self):
        if not self.olm:
            return False

        return self.olm.should_upload_keys

    def _handle_login(self, response):
        # type: (LoginResponse) -> None
        self.access_token = response.access_token
        self.user_id = response.user_id
        self.device_id = response.device_id

        if self.session_dir:
            self.olm = Olm(self.user_id, self.device_id, self.session_dir)

    def _handle_sync(self, response):
        # type: (SyncRepsponse) -> None
        if self.next_batch == response.next_batch:
            return

        self.next_batch = response.next_batch
        if self.olm:
            self.olm.uploaded_key_count = (
                response.device_key_count.signed_curve25519)

        for event in response.to_device_events:
            if isinstance(event, RoomEncryptedEvent):
                if not self.olm:
                    continue
                self.olm.decrypt_event(event)

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

            decrypted_events = []

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

    def receive(
        self,
        request_type,   # type: Union[str, RequestType]
        json_string,    # type: str
        uuid=None,      # type: Optional[UUID]
        timing=None     # type: Optional[TimingInfo]
    ):
        # type: (...) -> bool
        try:
            parsed_dict = json.loads(json_string, encoding="utf-8") \
                # type: Dict[Any, Any]
        except JSONDecodeError as e:
            raise RemoteProtocolError("Error parsing json: {}".format(str(e)))

        if isinstance(request_type, str):
            try:
                request_type = RequestType[request_type]
            except KeyError:
                raise LocalProtocolError("Invalid request type {}".format(
                    request_type))

        response = TypedResponse(request_type, parsed_dict, uuid, timing)
        self.parse_queue.append(response)

        return True

    def next_response(self, max_events=0):
        # type: (int) -> Optional[Response]
        if not self.parse_queue:
            return None

        typed_response = self.parse_queue.popleft()

        response = None  # type: Optional[Response]

        if typed_response.type is RequestType.login:
            response = LoginResponse.from_dict(typed_response.data)
            self._handle_login(response)
        elif typed_response.type is RequestType.sync:
            response = SyncRepsponse.from_dict(typed_response.data)
            self._handle_sync(response)
        elif typed_response.type is RequestType.room_send:
            response = RoomSendResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_put_state:
            response = RoomPutStateResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_redact:
            response = RoomRedactResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_kick:
            response = RoomKickResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_invite:
            response = RoomInviteResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.join:
            response = JoinResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_leave:
            response = RoomLeaveResponse.from_dict(typed_response.data)
        elif typed_response.type is RequestType.room_messages:
            response = RoomMessagesResponse.from_dict(typed_response.data)
            self._handle_messages_response(response)
        elif typed_response.type is RequestType.keys_upload:
            response = KeysUploadResponse.from_dict(typed_response.data)
            self._handle_olm_response(response)

        if not response:
            raise NotImplementedError(
                "Response type {} not implemented".format(typed_response.type)
            )

        response.uuid = typed_response.uuid
        if typed_response.timing:
            response.start_time = typed_response.timing.start
            response.end_time = typed_response.timing.end
        return response


class HttpClient(object):
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
        self.response_queue = deque()  # type: Deque[TransportResponse]

        self._client = Client(user, device_id, session_dir)
        self.api = None  # type: Optional[Union[HttpApi, Http2Api]]
        self.connection = None \
            # type: Optional[Union[HttpConnection, Http2Connection]]

    def _send(self, request):
        # type: (TransportRequest) -> Tuple[UUID, bytes]
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        uuid, data = self.connection.send(request)
        return uuid, data

    @property
    def user(self):
        return self._client.user

    @user.setter
    def user(self, user):
        self._client.user = user

    @property
    def olm_account_shared(self):
        return self._client.olm_account_shared

    @property
    def should_upload_keys(self):
        return self._client.should_upload_keys

    @property
    def logged_in(self):
        return self._client.logged_in

    @property
    def device_id(self):
        return self._client.device_id

    @device_id.setter
    def device_id(self, device_id):
        self._client.device_id = device_id

    @property
    def rooms(self):
        return self._client.rooms

    @property
    def invited_rooms(self):
        return self._client.invited_rooms

    @property
    def lag(self):
        # type: () -> float
        if not self.connection:
            return 0

        uuid, elapsed = self.connection.elapsed

        if not uuid:
            return 0

        request_info = self.requests_made[uuid]
        # The timestamp are in seconds and the timeout is in ms
        lag = max(0, elapsed - (request_info.timeout / 1000))

        return lag

    def connect(self, transport_type=TransportType.HTTP):
        # type: (Optional[TransportType]) -> bytes
        if transport_type == TransportType.HTTP:
            self.connection = HttpConnection()
            self.api = HttpApi(self.host)
        elif transport_type == TransportType.HTTP2:
            self.connection = Http2Connection()
            self.api = Http2Api(self.host)
        else:
            raise NotImplementedError

        return self.connection.connect()

    def disconnect(self):
        # type: () -> bytes
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        data = self.connection.disconnect()
        self.connection = None
        self.api = None
        return data

    def data_to_send(self):
        # type: () -> bytes
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        return self.connection.data_to_send()

    def login(self, password, device_name=""):
        # type: (str, Optional[str]) -> Tuple[UUID, bytes]
        if not self.api:
            raise LocalProtocolError("Not connected.")

        if not self._client.user:
            raise LocalProtocolError("No user defined.")

        request = self.api.login(
            self._client.user, password, device_name, self._client.device_id
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.login, 0)
        return uuid, data

    def room_send(self, room_id, message_type, content):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_send(
            self._client.access_token, room_id, message_type, content
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_send, 0)
        return uuid, data

    def room_put_state(self, room_id, event_type, body):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_put_state(
            self._client.access_token, room_id, event_type, body
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_put_state, 0)
        return uuid, data

    def room_redact(self, room_id, event_id, reason=None):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_redact(
            self._client.access_token, room_id, event_id, reason
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_redact, 0)
        return uuid, data

    def room_kick(self, room_id, user_id, reason=None):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_kick(
            self._client.access_token, room_id, user_id, reason
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_kick, 0)
        return uuid, data

    def room_invite(self, room_id, user_id):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_invite(
            self._client.access_token, room_id, user_id
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_invite, 0)
        return uuid, data

    def join(self, room_id):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.join(self._client.access_token, room_id)

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.join, 0)
        return uuid, data

    def room_leave(self, room_id):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_leave(self._client.access_token, room_id)

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_leave, 0)
        return uuid, data

    def room_messages(
        self,
        room_id,
        start,
        end=None,
        direction=MessageDirection.back,
        limit=10
    ):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_messages(
            self._client.access_token,
            room_id,
            start,
            end,
            direction,
            limit
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.room_messages, 0)
        return uuid, data

    def keys_upload(self):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        keys_dict = self._client.olm.share_keys()

        logger.debug(pprint.pformat(keys_dict))

        request = self.api.keys_upload(self._client.access_token, keys_dict)

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.keys_upload, 0)
        return uuid, data

    def sync(self, timeout=None, filter=None):
        # type: (Optional[int], Optional[Dict[Any, Any]]) -> Tuple[UUID, bytes]
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.sync(
            self._client.access_token, self._client.next_batch, timeout, filter
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo(RequestType.sync, timeout or 0)
        return uuid, data

    def receive(self, data):
        # type: (bytes) -> None
        if not self.connection:
            raise LocalProtocolError("Not connected.")

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
                timing = TimingInfo(response.send_time, response.receive_time)
                self._client.receive(
                    request_info.type, response.text, response.uuid, timing
                )
            else:
                logger.info(
                    (
                        "Error with response of type type: {}, "
                        "error code {}"
                    ).format(request_info.type, response.status_code)
                )

                response.request_info = request_info
                self.response_queue.append(response)
        return

    def next_response(self, max_events=0):
        # type: (int) -> Optional[Union[TransportResponse, Response]]
        if self.response_queue:
            return self.response_queue.popleft()

        return self._client.next_response(max_events)
        return self._client.next_response(max_events)
