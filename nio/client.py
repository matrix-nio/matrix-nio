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
from uuid import UUID
from collections import deque, namedtuple
from typing import *

import h11
import h2

from logbook import Logger
from builtins import bytes, str

from .api import Http2Api, HttpApi
from .exceptions import (
    LocalProtocolError,
    RemoteTransportError,
    RemoteProtocolError
)
from .http import (Http2Connection, Http2Request, HttpConnection, HttpRequest,
                   TransportResponse, TransportType, TransportRequest)
from .log import logger_group

from .responses import (
    LoginResponse,
    Response,
    SyncRepsponse,
    RoomSendResponse,
    RoomPutStateResponse
)

from .rooms import MatrixRoom

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


logger = Logger('nio.client')
logger_group.add_logger(logger)


TypedResponse = namedtuple("TypedResponse", ["type", "data", "uuid", "timing"])
TimingInfo = namedtuple("TimingInfo", ["start", "end"])
RequestInfo = namedtuple("RequestInfo", ["type", "timeout"])


class Client(object):
    def __init__(
            self,
            user=None,       # type: Optional[str]
            device_id=None,  # type: Optional[str]
            session_dir="",  # type: Optional[str]
    ):
        # type: (...) -> None
        self.user = user
        self.device_id = device_id
        self.session_dir = session_dir
        self.parse_queue = deque()  # type: Deque[TypedResponse]

        self.user_id = ""
        self.access_token = ""
        self.next_batch = ""

        self.rooms = dict()  # type: Dict[str, MatrixRoom]

    def _load_olm(self):
        # TODO load the olm account and sessions from the session dir
        return False

    @property
    def logged_in(self):
        # type: () -> bool
        return True if self.access_token else False

    def _handle_response(self, response):
        # type: (Response) -> None
        if isinstance(response, LoginResponse):
            self.access_token = response.access_token
            self.user_id = response.user_id
            self.device_id = response.device_id
        elif isinstance(response, SyncRepsponse):
            if self.next_batch == response.next_batch:
                return

            self.next_batch = response.next_batch

            for room_id, join_info in response.rooms.join.items():
                if room_id not in self.rooms:
                    logger.info("New joined room {}".format(room_id))
                    self.rooms[room_id] = MatrixRoom(room_id, self.user_id)

                room = self.rooms[room_id]

                for event in join_info.state:
                    room.handle_event(event)

                for event in join_info.timeline.events:
                    room.handle_event(event)

    def receive(self, response_type, json_string, uuid=None, timing=None):
        # type: (str, str, Optional[UUID], Optional[TimingInfo]) -> bool
        try:
            parsed_dict = json.loads(json_string, encoding="utf-8")  \
                # type: Dict[Any, Any]
        except JSONDecodeError as e:
            raise RemoteProtocolError("Error parsing json: {}".format(str(e)))

        response = TypedResponse(response_type, parsed_dict, uuid, timing)
        self.parse_queue.append(response)

        return True

    def next_response(self, max_events=0):
        # type: (int) -> Optional[Response]
        if not self.parse_queue:
            return None

        typed_response = self.parse_queue.popleft()

        if typed_response.type == "login":
            response = LoginResponse.from_dict(typed_response.data)  \
                # type: Response
            self._handle_response(response)
        elif typed_response.type == "sync":
            response = SyncRepsponse.from_dict(typed_response.data)
            self._handle_response(response)
        elif typed_response.type == "room_send":
            response = RoomSendResponse.from_dict(typed_response.data)
        elif typed_response.type == "room_put_state":
            response = RoomPutStateResponse.from_dict(typed_response.data)

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
            device_id="",    # type: Optional[str]
            session_dir="",  # type: Optional[str]
    ):
        # type: (...) -> None
        self.host = host
        self.requests_made = {}        # type: Dict[UUID, RequestInfo]
        self.response_queue = deque()  # type: Deque[TransportResponse]

        self._client = Client(user, device_id, session_dir)
        self.api = None         # type: Optional[Union[HttpApi, Http2Api]]
        self.connection = None  \
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
    def rooms(self):
        return self._client.rooms

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
            self._client.user,
            password,
            device_name,
            self._client.device_id
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo("login", 0)
        return uuid, data

    def room_send(self, room_id, message_type, content):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_send(
            self._client.access_token,
            room_id,
            message_type,
            content)

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo("room_send", 0)
        return uuid, data

    def room_put_state(self, room_id, event_type, body):
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.room_put_state(
            self._client.access_token,
            room_id,
            event_type,
            body)

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo("room_put_state", 0)
        return uuid, data

    def sync(self, timeout=None, filter=None):
        # type: (Optional[int], Optional[Dict[Any, Any]]) -> Tuple[UUID, bytes]
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.sync(
            self._client.access_token,
            self._client.next_batch,
            timeout,
            filter
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = RequestInfo("sync", timeout or 0)
        return uuid, data

    def receive(self, data):
        # type: (bytes) -> None
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        try:
            response = self.connection.receive(data)
        except (
            h11.RemoteProtocolError,
            h2.exceptions.ProtocolError
        ) as e:
            raise RemoteTransportError(e)

        if response:
            try:
                request_info = self.requests_made.pop(response.uuid)
            except KeyError:
                logger.error("{}".format(pprint.pformat(self.requests_made)))
                raise

            if response.is_ok:
                logger.info("Received response of type: {}".format(
                    request_info.type))
                timing = TimingInfo(response.send_time, response.receive_time)
                self._client.receive(
                    request_info.type,
                    response.text,
                    response.uuid,
                    timing
                )
            else:
                logger.info(("Error with response of type type: {}, "
                             "error code {}").format(
                            request_info.type, response.status_code))

                response.request_info = request_info
                self.response_queue.append(response)
        return

    def next_response(self, max_events=0):
        # type: (int) -> Optional[Union[TransportResponse, Response]]
        if self.response_queue:
            return self.response_queue.popleft()

        return self._client.next_response(max_events)
