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
from builtins import bytes
from collections import OrderedDict
from enum import Enum, unique
from typing import *
from uuid import uuid4

import h2.connection
import h2.events
import h11

from . import USER_AGENT


@unique
class TransportType(Enum):
    HTTP = 0
    HTTP2 = 1
    WEBSOCKETS = 2


@unique
class RequestType(Enum):
    LOGIN = 0
    SYNC = 1


class TransportRequest(object):
    def __init__(self, request, data=b""):
        self._request = request
        self._data = data

    @classmethod
    def get(host, target, data=None):
        raise NotImplementedError

    @classmethod
    def post(host, target, data):
        raise NotImplementedError

    @classmethod
    def put(host, target, data):
        raise NotImplementedError


class HttpRequest(TransportRequest):
    def __init__(self, request, data=b""):
        super(HttpRequest, self).__init__(request, data)
        self._end_of_message = h11.EndOfMessage()

    @classmethod
    def get(cls, host, target):
        request = h11.Request(
            method="GET",
            target=target,
            headers=HttpRequest._headers(host)
        )

        return cls(request)

    @staticmethod
    def _headers(host, data=None):
        # type (str, bytes) -> List[Tuple[str, str]]
        headers = [
            ("User-Agent", "{agent}".format(agent=USER_AGENT)),
            ("Host", "{host}".format(host=host)),
            ("Connection", "keep-alive"),
            ("Accept", "*/*")
        ]

        if data:
            headers.append(
                ("Content-Type", "application/x-www-form-urlencoded")
            )

            headers.append(
                ("Content-length", "{length}".format(length=len(data)))
            )

        return headers

    @classmethod
    def _post_or_put(cls, method, host, target, data):
        request_data = (json.dumps(data, separators=(',', ':'))
                        if isinstance(data, dict) else data)

        request_data = bytes(request_data, "utf-8")

        request = h11.Request(
            method=method,
            target=target,
            headers=HttpRequest._headers(host, request_data)
        )

        d = h11.Data(data=request_data)

        return cls(request, d)

    @classmethod
    def post(cls, host, target, data):
        return cls._post_or_put("POST", host, target, data)

    @classmethod
    def put(cls, host, target, data):
        return cls._post_or_put("PUT", host, target, data)


class Http2Request(TransportRequest):
    @staticmethod
    def _request(method, target, headers):
        h = [
            (":method", method),
            (":path", target)
        ]

        h = h + headers

        return h

    @staticmethod
    def _headers(host, data=None):
        # type (str, bytes) -> List[Tuple[str, str]]
        headers = [
            (":authority", "{host}".format(host=host)),
            (":scheme", "https"),
            ("user-agent", "{agent}".format(agent=USER_AGENT)),
        ]

        if data:
            headers.append(
                ("content-type", "application/x-www-form-urlencoded")
            )

            headers.append(
                ("content-length", "{length}".format(length=len(data)))
            )

        return headers

    @classmethod
    def post(cls, host, target, data):
        request_data = (json.dumps(data, separators=(',', ':'))
                        if isinstance(data, dict) else data)

        request_data = bytes(request_data, "utf-8")

        request = Http2Request._request(
            method="POST",
            target=target,
            headers=Http2Request._headers(host, request_data)
        )

        return cls(request, request_data)

    @classmethod
    def get(cls, host, target):
        request = Http2Request._request(
            method="GET",
            target=target,
            headers=Http2Request._headers(host)
        )

        return cls(request)


class TransportResponse(object):
    def __init__(self, responses=None, data=b""):
        # type: (List[Any], bytes) -> None
        self.responses = responses if responses else []
        self.data = data

    def __repr__(self):
        return repr(self.responses) + repr(self.data)

    def add_response(self, response):
        raise NotImplementedError

    def add_data(self, data):
        raise NotImplementedError

    @property
    def is_ok(self):
        last = self.responses[-1]
        if last.status_code == 200:
            return True

        return False


class HttpResponse(TransportResponse):
    def add_response(self, response):
        # type: (Union[h11.Response, h11.InformationalResponse]) -> None
        self.responses.append(response)

    def add_data(self, data):
        # type: (bytes) -> None
        self.data = self.data + data


class Http2Response(TransportResponse):
    def add_response(self, response):
        # type: (Union[h11.Response, h11.InformationalResponse]) -> None
        self.responses.append(response)

    def add_data(self, data):
        # type: (bytes) -> None
        self.data = self.data + data


class Request(object):
    def __init__(self, request_type, request):
        # type: (RequestType, TransportRequest) -> None
        self.type = request_type
        self.request = request


class Connection(object):
    def connect(self):
        # type: () -> bytes
        return b""

    def disconnect(self):
        # type: () -> bytes
        return b""


class HttpConnection(Connection):
    def __init__(self):
        # type: () -> None
        self._connection = h11.Connection(our_role=h11.CLIENT)
        self._message_queue = OrderedDict()  # type: OrderedDict
        self._current_uuid = None      # type: Optional[str]
        self._current_response = None  # type: Optional[HttpResponse]

    def data_to_send(self):
        # type: () -> bytes
        if self._current_uuid:
            return b""

        if not self._message_queue:
            return b""

        if not self._connection.our_state == h11.IDLE:
            return b""

        uuid, request = self._message_queue.popitem(last=False)
        _, data = self.send(request)
        return data

    def send(self, mrequest):
        # type: (Request) -> Tuple[str, bytes]
        data = b""

        if not isinstance(mrequest, HttpRequest):
            raise TypeError("Invalid request type for HttpConnection")

        if self._connection.our_state == h11.IDLE:
            data = data + self._connection.send(mrequest._request)

            if mrequest._data:
                data = data + self._connection.send(mrequest._data)

            data = data + self._connection.send(
                mrequest._end_of_message
            )

            self._current_uuid = uuid4()
            return self._current_uuid, data
        else:
            uuid = uuid4()
            self._message_queue[uuid] = mrequest
            return uuid, b""

    def _get_response(self):
        # type: () -> Tuple[Optional[str], Optional[HttpResponse]]
        ret = self._connection.next_event()

        if not self._current_response:
            self._current_response = HttpResponse()

        while ret != h11.NEED_DATA:
            if ret == h11.PAUSED or isinstance(ret, h11.EndOfMessage):
                self._connection.start_next_cycle()
                response = self._current_response
                uuid = self._current_uuid
                self._current_response = None
                self._current_uuid = None
                return uuid, response
            elif isinstance(ret, h11.InformationalResponse):
                self._current_response.add_response(ret)
            elif isinstance(ret, h11.Response):
                self._current_response.add_response(ret)
            elif isinstance(ret, h11.Data):
                self._current_response.add_data(ret.data)

            ret = self._connection.next_event()

        return None, None

    def receive(self, data):
        self._connection.receive_data(data)
        return self._get_response()


class Http2Connection(Connection):
    def __init__(self):
        # type: () -> None
        self._connection = h2.connection.H2Connection()
        self._responses = {}  # type: Dict[int, Http2Response]

    def send(self, mrequest):
        # type: (Request) -> bytes
        if not isinstance(mrequest, Http2Request):
            raise TypeError("Invalid request type for HttpConnection")

        stream_id = self._connection.get_next_available_stream_id()
        self._connection.send_headers(stream_id, mrequest._request)
        # TODO we need to split the data here according to window
        # and frame size.
        self._connection.send_data(stream_id, mrequest._data)
        # TODO store the request type so we know how to parse the response on
        # this stream id.
        self._connection.end_stream(stream_id)
        ret = self._connection.data_to_send()
        self._responses[stream_id] = Http2Response()

        return ret

    def connect(self):
        # type: () -> bytes
        self._connection.initiate_connection()
        return self._connection.data_to_send()

    def disconnect(self):
        # type: () -> bytes
        self._connection.close_connection()
        return self._connection.data_to_send()

    def _handle_headers(self, event):
        # type: (h2.events.Event) -> None
        stream_id = event.stream_id
        headers = event.headers

        response = self._responses[stream_id]
        response.add_response(headers)

    def _handle_data(self, event):
        # type: (h2.events.Event) -> None
        stream_id = event.stream_id
        data = event.data

        response = self._responses[stream_id]
        response.add_data(data)

    def _handle_events(self, events):
        # type: (h2.events.Event) -> Optional[Http2Response]
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                self._handle_headers(event)
            elif isinstance(event, h2.events.DataReceived):
                self._handle_data(event)
            elif isinstance(event, h2.events.StreamEnded):
                response = self._responses.pop(event.stream_id)
                return response
            elif isinstance(event, h2.events.SettingsAcknowledged):
                pass
            elif isinstance(event, h2.events.StreamReset):
                # TODO signal an error
                self._responses.pop(event.stream_id)
            elif isinstance(event, h2.events.WindowUpdated):
                pass

        return None

    def receive(self, data):
        # type: (bytes) -> Optional[Http2Response]
        events = self._connection.receive_data(data)
        return self._handle_events(events)
