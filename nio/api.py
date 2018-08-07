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

from .exceptions import LocalProtocolError
from .http import Http2Request, HttpRequest, TransportRequest

try:
    from urllib.parse import quote, urlencode, urlparse
except ImportError:
    from urllib import quote, urlencode  # type: ignore
    from urlparse import urlparse        # type: ignore


MATRIX_API_PATH = "/_matrix/client/r0"  # type: str


class Api(object):
    @staticmethod
    def to_json(content_dict):
        # type: (Dict[Any, Any]) -> str
        return json.dumps(content_dict, separators=(',', ':'))

    @staticmethod
    def _build_path(path, query_parameters=None):
        # type: (str, dict) -> str
        path = ("{api}/{path}").format(api=MATRIX_API_PATH, path=path)

        if query_parameters:
            path += "?{}".format(urlencode(query_parameters))

        return path

    @staticmethod
    def login(user, password, device_name="", device_id=""):
        # type: (str, str, Optional[str], Optional[str]) -> Tuple[str, str]
        path = Api._build_path("login")

        content_dict = {
            "type": "m.login.password",
            "user": user,
            "password": password
        }

        if device_id:
            content_dict["device_id"] = device_id

        if device_name:
            content_dict["initial_device_display_name"] = device_name

        return path, Api.to_json(content_dict)

    @staticmethod
    def sync(
        access_token,     # type: str
        next_batch=None,  # type: Optional[str]
        timeout=None,     # type: Optional[int]
        filter=None       # type: Optional[Dict[Any, Any]]
    ):
        # type: (...) -> str
        query_parameters = {"access_token": access_token}

        if next_batch:
            query_parameters["since"] = next_batch

        if timeout:
            query_parameters["timeout"] = str(timeout)

        if filter:
            filter_json = json.dumps(filter, separators=(',', ':'))
            query_parameters["filter"] = filter_json

        return Api._build_path("sync", query_parameters)

    @staticmethod
    def room_send(access_token, room_id, msg_type, content, tx_id):
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/send/{msg_type}/{tx_id}".format(
            room=room_id, msg_type=msg_type, tx_id=tx_id)

        return Api._build_path(path, query_parameters), Api.to_json(content)

    @staticmethod
    def room_put_state(access_token, room_id, event_type, body):
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/state/{event_type}".format(
            room=room_id, event_type=event_type)

        return Api._build_path(path, query_parameters), Api.to_json(body)


class HttpApi(object):
    def __init__(self, host):
        # type: (str) -> None
        self.host = host
        self._txn_id = 0

    @property
    def txn_id(self):
        # type: () -> int
        ret = self._txn_id
        self._txn_id += 1
        return ret

    def _build_request(self, method, path, data=None):
        if method == "GET":
            return HttpRequest.get(self.host, path)
        elif method == "POST":
            return HttpRequest.post(self.host, path, data)
        elif method == "PUT":
            return HttpRequest.put(self.host, path, data)
        else:
            raise LocalProtocolError("Invalid request method")

    def login(self, user, password, device_name="", device_id=""):
        # type: (str, str, Optional[str], Optional[str]) -> TransportRequest
        path, post_data = Api.login(
            user,
            password,
            device_name,
            device_id
        )
        return self._build_request("POST", path, post_data)

    def sync(
        self,
        access_token,     # type: str
        next_batch=None,  # type: Optional[str]
        timeout=None,     # type: Optional[int]
        filter=None       # type: Optional[Dict[Any, Any]]
    ):
        # type: (...) -> TransportRequest
        path = Api.sync(access_token, next_batch, timeout, filter)
        return self._build_request("GET", path)

    def room_send(self, access_token, room_id, msg_type, content):
        # type: (str, str, str, Dict[Any, Any]) -> TransportRequest
        path, data = Api.room_send(
            access_token,
            room_id,
            msg_type,
            content,
            self.txn_id
        )
        return self._build_request("PUT", path, data)

    def room_put_state(self, access_token, room_id, event_type, body):
        path, data = Api.room_put_state(
            access_token,
            room_id,
            event_type,
            body
        )
        return self._build_request("PUT", path, data)


class Http2Api(HttpApi):
    def _build_request(self, method, path, data=None):
        if method == "GET":
            return Http2Request.get(self.host, path)
        elif method == "POST":
            return Http2Request.post(self.host, path, data)
        elif method == "PUT":
            return Http2Request.put(self.host, path, data)
        else:
            raise LocalProtocolError("Invalid request method")
