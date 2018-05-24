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
from typing import *


try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore

from . responses import Response, LoginResponse
from . exceptions import LocalProtocolError, RemoteTransportError
from . api import HttpApi, Http2Api
from . http import (
    Request,
    TransportType,
    Http2Connection,
    HttpConnection,
    Http2Request,
    HttpRequest
)


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

        self.user_id = ""
        self.access_token = ""
        self.next_batch = ""

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

    def receive(self, response_type, json_string):
        # type: (str, Union[str, bytes]) -> Response
        try:
            parsed_dict = json.loads(json_string, encoding="utf-8")  \
                # type: Dict[Any, Any]
        except ValueError as e:
            # TODO return a error response
            return None

        if response_type == "login":
            response = LoginResponse.from_dict(parsed_dict)
            self._handle_response(response)
            return response

        # TODO parse the other response types
        return parsed_dict


class HttpClient(object):
    def __init__(
            self,
            host,  # type: str
            user,  # type: str
            device_id="",    # type: Optional[str]
            session_dir="",  # type: Optional[str]
    ):
        # type: (...) -> None
        self.host = host
        self.requests_made = {}  # type: Dict[str, str]

        self._client = Client(user, device_id, session_dir)
        self.api = None         # type: Optional[Union[HttpApi, Http2Api]]
        self.connection = None  \
            # type: Optional[Union[HttpConnection, Http2Connection]]

    def _send(self, request):
        # type: (Request) -> Tuple[str, bytes]
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        uuid, data = self.connection.send(request)
        return uuid, data

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
        # type: (str, Optional[str]) -> bytes
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
        self.requests_made[uuid] = "login"
        return data

    def sync(self, filter=None):
        # type: (Optional[Dict[Any, Any]]) -> bytes
        if not self._client.logged_in:
            raise LocalProtocolError("Not logged in.")

        if not self.api:
            raise LocalProtocolError("Not connected.")

        request = self.api.sync(
            self._client.access_token,
            self._client.next_batch,
            filter
        )

        uuid, data = self._send(request)
        self.requests_made[uuid] = "sync"
        return data

    def receive(self, data):
        # type: (bytes) -> Optional[Response]
        # TODO turn the TransportResponse in a MatrixResponse
        if not self.connection:
            raise LocalProtocolError("Not connected.")

        uuid, transport_response = self.connection.receive(data)

        if transport_response:
            if transport_response.is_ok:
                request_type = self.requests_made.pop(uuid)
                response = self._client.receive(request_type,
                                                transport_response.data)
                return response
            else:
                # TODO return an error repsonse
                raise RemoteTransportError

        return None
