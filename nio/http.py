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

from __future__ import annotations

import json
import logging
import pprint
import time
from collections import OrderedDict, deque
from enum import Enum, unique
from typing import Any, Deque, List, Optional, Tuple
from uuid import UUID, uuid4

import h2.connection
import h2.events
import h11

logger = logging.getLogger(__name__)

USER_AGENT = "nio"


@unique
class TransportType(Enum):
    HTTP = 0
    HTTP2 = 1
    WEBSOCKETS = 2


class TransportRequest:
    def __init__(self, request, data=b"", timeout=0):
        self._request = request
        self._data = data
        self.response = None  # Optional[TransportResponse]
        self.timeout = timeout

    @classmethod
    def get(cls, host, target, timeout=0):
        raise NotImplementedError

    @classmethod
    def post(cls, host, target, data, timeout=0):
        raise NotImplementedError

    @classmethod
    def put(cls, host, target, data, timeout=0):
        raise NotImplementedError


class HttpRequest(TransportRequest):
    def __init__(self, request, data=b"", timeout=0):
        super().__init__(request, data, timeout)
        self._end_of_message = h11.EndOfMessage()

    @classmethod
    def get(cls, host, target, timeout=0):
        request = h11.Request(
            method="GET", target=target, headers=HttpRequest._headers(host)
        )

        return cls(request, timeout=timeout)

    @staticmethod
    def _headers(host: str, data: Optional[bytes] = None) -> List[Tuple[str, str]]:
        headers = [
            ("User-Agent", f"{USER_AGENT}"),
            ("Host", f"{host}"),
            ("Connection", "keep-alive"),
            ("Accept", "*/*"),
        ]

        if data:
            headers.append(("Content-Type", "application/json"))

            headers.append(("Content-length", f"{len(data)}"))

        return headers

    @classmethod
    def _post_or_put(cls, method, host, target, data, timeout=0):
        request_data = (
            json.dumps(data, separators=(",", ":")) if isinstance(data, dict) else data
        )

        request_data = bytes(request_data, "utf-8")

        request = h11.Request(
            method=method,
            target=target,
            headers=HttpRequest._headers(host, request_data),
        )

        d = h11.Data(data=request_data)

        return cls(request, d, timeout)

    @classmethod
    def post(cls, host, target, data, timeout=0):
        return cls._post_or_put("POST", host, target, data, timeout)

    @classmethod
    def put(cls, host, target, data, timeout=0):
        return cls._post_or_put("PUT", host, target, data, timeout)


class Http2Request(TransportRequest):
    @staticmethod
    def _request(method, target, headers):
        h = [(":method", method), (":path", target)]

        h = h + headers

        return h

    @staticmethod
    def _headers(host: str, data: Optional[bytes] = None) -> List[Tuple[str, str]]:
        headers = [
            (":authority", f"{host}"),
            (":scheme", "https"),
            ("user-agent", f"{USER_AGENT}"),
        ]

        headers.append(("accept", "application/json"))

        if data:
            headers.append(("content-type", "application/json"))

            headers.append(("content-length", f"{len(data)}"))

        return headers

    @classmethod
    def _post_or_put(cls, method, host, target, data, timeout):
        request_data = (
            json.dumps(data, separators=(",", ":")) if isinstance(data, dict) else data
        )

        request_data = bytes(request_data, "utf-8")

        request = Http2Request._request(
            method=method,
            target=target,
            headers=Http2Request._headers(host, request_data),
        )

        return cls(request, request_data, timeout)

    @classmethod
    def put(cls, host, target, data, timeout=0):
        return cls._post_or_put("PUT", host, target, data, timeout)

    @classmethod
    def post(cls, host, target, data, timeout=0):
        return cls._post_or_put("POST", host, target, data, timeout)

    @classmethod
    def get(cls, host, target, timeout=0):
        request = Http2Request._request(
            method="GET",
            target=target,
            headers=Http2Request._headers(host),
        )

        return cls(request, timeout=timeout)


class HeaderDict(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())


class TransportResponse:
    def __init__(self, uuid: Optional[UUID] = None, timeout: float = 0) -> None:
        self.headers: HeaderDict = HeaderDict()
        self.content: bytes = b""
        self.status_code: Optional[int] = None
        self.uuid = uuid or uuid4()
        self.creation_time = time.time()
        self.timeout: float = timeout
        self.send_time: Optional[float] = None
        self.receive_time: Optional[float] = None
        self.request_info: Optional[Any] = None

    def add_response(self, response):
        raise NotImplementedError

    def add_data(self, content: bytes) -> None:
        self.content = self.content + content

    def mark_as_sent(self):
        self.send_time = time.time()

    def mark_as_received(self):
        self.receive_time = time.time()

    @property
    def elapsed(self) -> float:
        if (self.receive_time is not None) and (self.send_time is not None):
            elapsed = self.receive_time - self.send_time

        elif self.send_time is not None:
            elapsed = time.time() - self.send_time

        else:
            elapsed = 0.0

        return max(0, elapsed - (self.timeout / 1000))

    @property
    def text(self):
        return self.content.decode("utf-8")

    @property
    def is_ok(self):
        if self.status_code == 200:
            return True

        return False


class HttpResponse(TransportResponse):
    def add_response(self, response: h11.Response) -> None:
        self.status_code = response.status_code

        for header in response.headers:
            _name, _value = header
            name = _name.decode("utf-8")
            value = _value.decode("utf-8")
            logger.debug(f"Got http header {name}: {value}")
            self.headers[name] = value


class Http2Response(TransportResponse):
    def __init__(self, uuid=None, timeout=0):
        super().__init__(uuid, timeout)
        self.was_reset = False
        self.error_code: Optional[h2.errors.ErrorCodes] = None

    def add_response(self, headers: h2.events.ResponseReceived) -> None:
        for header in headers:
            name, value = header
            logger.debug(f"Got http2 header {name}: {value}")

            if name == b":status" or name == ":status":
                self.status_code = int(value)
            else:
                self.headers[name] = value

    @property
    def is_ok(self):
        if self.was_reset:
            return False

        if self.status_code == 200:
            return True

        return False


class Connection:
    def connect(self) -> bytes:
        return b""

    def disconnect(self) -> bytes:
        return b""


class HttpConnection(Connection):
    def __init__(self) -> None:
        self._connection = h11.Connection(our_role=h11.CLIENT)
        self._message_queue: Deque[HttpRequest] = deque()
        self._current_response: Optional[HttpResponse] = None

    def data_to_send(self) -> bytes:
        if self._current_response:
            return b""

        if not self._message_queue:
            return b""

        if not self._connection.our_state == h11.IDLE:
            return b""

        request = self._message_queue.popleft()
        _, data = self.send(request)
        return data

    @property
    def elapsed(self) -> float:
        if not self._current_response:
            return 0

        response = self._current_response

        return response.elapsed

    def send(
        self, request: TransportRequest, uuid: Optional[UUID] = None
    ) -> Tuple[UUID, bytes]:
        data = b""

        if not isinstance(request, HttpRequest):
            raise TypeError("Invalid request type for HttpConnection")

        if self._connection.our_state == h11.IDLE and not self._current_response:
            data = data + self._connection.send(request._request)

            if request._data:
                data = data + self._connection.send(request._data)

            data = data + self._connection.send(request._end_of_message)

            if request.response:
                self._current_response = request.response
            else:
                self._current_response = HttpResponse(uuid, request.timeout)

            # Make mypy happy
            assert self._current_response

            self._current_response.mark_as_sent()
            return self._current_response.uuid, data
        else:
            request.response = HttpResponse(uuid, request.timeout)
            self._message_queue.append(request)
            return request.response.uuid, b""

    def _get_response(self) -> Optional[HttpResponse]:
        ret = self._connection.next_event()

        if not self._current_response:
            self._current_response = HttpResponse()

        while ret != h11.NEED_DATA:
            if ret == h11.PAUSED or isinstance(ret, h11.EndOfMessage):
                try:
                    self._connection.start_next_cycle()
                except h11.ProtocolError:
                    self._connection = h11.Connection(our_role=h11.CLIENT)
                response = self._current_response
                self._current_response = None
                response.mark_as_received()
                return response
            elif isinstance(ret, h11.InformationalResponse):
                pass
            elif isinstance(ret, h11.Response):
                self._current_response.add_response(ret)
            elif isinstance(ret, h11.Data):
                self._current_response.add_data(ret.data)

            ret = self._connection.next_event()

        return None

    def receive(self, data):
        self._connection.receive_data(data)
        return self._get_response()


class Http2Connection(Connection):
    def __init__(self) -> None:
        config = h2.config.H2Configuration(
            client_side=True, validate_inbound_headers=False
        )
        self._connection = h2.connection.H2Connection(config=config)
        self._connection.max_inbound_frame_size = 64 * 1024
        self._responses: OrderedDict[int, Http2Response] = OrderedDict()
        self._data_to_send: OrderedDict[int, bytes] = OrderedDict()

    @property
    def elapsed(self) -> float:
        if not self._responses:
            return 0

        return max(response.elapsed for response in self._responses.values())

    def _handle_window_update(self, event):
        # We don't have any data to send, it doesn't matter that the window got
        # updated.
        if not self._data_to_send:
            return

        # The window changed for a single stream and the stream contains some
        # data to send, send it out now.
        if event.stream_id in self._data_to_send:
            self._send_data(event.stream_id, self._data_to_send[event.stream_id])
            return

        # The window changed for the whole connection, try to send out data for
        # every stream we have some data buffered.
        if event.stream_id == 0:
            for stream_id, data in self._data_to_send.items():
                self._send_data(stream_id, data)

    def _send_data(self, stream_id, data):
        window_size = self._connection.local_flow_control_window(stream_id)
        max_frame_size = self._connection.max_outbound_frame_size
        request_size = len(data)

        bytes_to_send = min(window_size, request_size)
        logger.debug(
            f"Sending data: stream id: {stream_id}; request size: {request_size}; "
            f"window size: {window_size}; max frame size {max_frame_size}"
        )

        while bytes_to_send > 0:
            chunk_size = min(bytes_to_send, max_frame_size)

            if chunk_size >= len(data):
                chunk, data = data, ""
            else:
                chunk, data = (data[0:chunk_size], data[chunk_size:])

            bytes_to_send -= chunk_size
            self._connection.send_data(stream_id, chunk)

        if not data:
            self._connection.end_stream(stream_id)
            self._data_to_send.pop(stream_id, None)
        else:
            self._data_to_send[stream_id] = data

    def send(
        self, request: TransportRequest, uuid: Optional[UUID] = None
    ) -> Tuple[UUID, bytes]:
        if not isinstance(request, Http2Request):
            raise TypeError("Invalid request type for HttpConnection")

        logger.debug(
            f"Making Http2 request {pprint.pformat(request._request)} {pprint.pformat(request._data)}."
        )

        stream_id = self._connection.get_next_available_stream_id()
        logger.debug(f"New stream id {stream_id}")

        self._connection.send_headers(stream_id, request._request)
        self._send_data(stream_id, request._data)
        ret = self._connection.data_to_send()

        response = Http2Response(uuid, request.timeout)
        response.mark_as_sent()

        self._responses[stream_id] = response

        return response.uuid, ret

    def data_to_send(self):
        return self._connection.data_to_send()

    def connect(self) -> bytes:
        self._connection.initiate_connection()
        return self._connection.data_to_send()

    def disconnect(self) -> bytes:
        self._connection.close_connection()
        self._responses.clear()
        self._data_to_send = OrderedDict()
        return self._connection.data_to_send()

    def _handle_response(self, event: h2.events.Event) -> None:
        stream_id = event.stream_id
        headers = event.headers

        response = self._responses[stream_id]
        response.add_response(headers)

    def _handle_data(self, event: h2.events.Event) -> None:
        stream_id = event.stream_id
        data = event.data

        self._connection.acknowledge_received_data(
            event.flow_controlled_length, event.stream_id
        )

        response = self._responses[stream_id]
        response.add_data(data)

    def _handle_reset(self, event: h2.events.StreamReset) -> Optional[Http2Response]:
        response = self._responses.pop(event.stream_id, None)

        if not response:
            return None

        response.was_reset = True
        response.error_code = event.error_code
        return response

    def _handle_events(self, events: h2.events.Event) -> Optional[Http2Response]:
        for event in events:
            logger.info(f"Handling Http2 event: {repr(event)}")

            if isinstance(event, h2.events.ResponseReceived):
                self._handle_response(event)
            elif isinstance(event, h2.events.DataReceived):
                self._handle_data(event)
            elif isinstance(event, h2.events.StreamEnded):
                response = self._responses.pop(event.stream_id, None)

                if not response:
                    return None

                response.mark_as_received()
                return response
            elif isinstance(event, h2.events.SettingsAcknowledged):
                pass
            elif isinstance(event, h2.events.WindowUpdated):
                self._handle_window_update(event)
            elif isinstance(event, h2.events.StreamReset):
                logger.error("Http2 stream reset")
                return self._handle_reset(event)
            elif isinstance(events, h2.events.ConnectionTerminated):
                logger.error("Http2 connection terminated")
                # TODO reset the client
                pass

        return None

    def receive(self, data: bytes) -> Optional[Http2Response]:
        events = self._connection.receive_data(data)
        return self._handle_events(events)
