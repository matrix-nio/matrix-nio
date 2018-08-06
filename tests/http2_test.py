# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import h2

from nio.client import HttpClient, TransportType, RequestInfo
from nio.http import TransportResponse, Http2Response
from nio.responses import LoginResponse, SyncRepsponse
from nio.api import Http2Api
from h2.events import (
    ResponseReceived,
    DataReceived,
    StreamEnded,
    RequestReceived
)


class TestClass(object):
    example_response_headers = [
        (':status', '200'),
        ('server', 'fake-serv/0.1.0')
    ]

    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename, "rb") as f:
            return f.read()

    def login_response(self, stream_id, frame_factory):
        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers, stream_id=stream_id
        )

        login_body = self._load_response("tests/data/login_response.json")

        data = frame_factory.build_data_frame(
            data=login_body,
            stream_id=stream_id,
            flags=['END_STREAM']
        )
        return f.serialize() + data.serialize()

    def sync_response(self, stream_id, frame_factory):
        f = frame_factory.build_headers_frame(
            headers=self.example_response_headers, stream_id=stream_id
        )

        body = self._load_response("tests/data/sync.json")

        data = frame_factory.build_data_frame(
            data=body,
            stream_id=stream_id,
            flags=['END_STREAM']
        )
        return f.serialize() + data.serialize()

    def test_client(self):
        client = HttpClient("localhost", "example")
        client.connect(TransportType.HTTP2)
        client.login("test")

        e = ResponseReceived()
        e.stream_id = 1
        e.headers = self.example_response_headers

        data = DataReceived()
        data.stream_id = 1
        data.flow_controlled_length = 88
        data.data = self._load_response("tests/data/login_response.json")

        end = StreamEnded()
        end.stream_id = 1

        response = client.connection._handle_events([e, data, end])
        assert isinstance(response, TransportResponse)
        assert response.status_code == 200
        assert response.is_ok

        client._client.receive("login", response.text)
        response = client.next_response()

        assert isinstance(response, LoginResponse)

        client.sync()

        e = ResponseReceived()
        e.stream_id = 3
        e.headers = self.example_response_headers

        data = DataReceived()
        data.stream_id = 3
        data.flow_controlled_length = 88
        data.data = self._load_response("tests/data/sync.json")

        end = StreamEnded()
        end.stream_id = 3

        response = client.connection._handle_events([e, data, end])

        assert isinstance(response, TransportResponse)
        assert response.status_code == 200
        assert response.is_ok

        client._client.receive("sync", response.text)
        response = client.next_response()

        assert isinstance(response, SyncRepsponse)

        content = {
            "body": "test",
            "msgtype": "m.text"
        }

        sync_uuid, _ = client.sync()
        uuid, _ = client.room_send(
            "!test:localhost",
            "m.room.message",
            content
        )

        connection = client.connection

        assert len(connection._responses) == 2

        send_response = connection._responses[7]
        sync_response = connection._responses[5]

        assert send_response.uuid == uuid
        assert sync_response.uuid == sync_uuid

    def test_api(self):
        content = {
            "body": "test",
            "msgtype": "m.text"
        }

        api = Http2Api("localhost")
        request = api.room_send(
            "token",
            "!test:localhost",
            "m.room.message",
            content
        )
        assert request._request

        # assert request._request == ""

    def test_client_lag(self, frame_factory):
        client = HttpClient("localhost", "example")
        client.connect(TransportType.HTTP2)
        response = Http2Response()
        response.send_time = 0
        response.receive_time = 30
        client.connection._responses[response.uuid] = response
        typed_response = RequestInfo("sync", 25 * 1000)
        client.requests_made[response.uuid] = typed_response

        assert client.lag == 5

    def test_client_receive(self, frame_factory):
        client = HttpClient("localhost", "example")
        client.connect(TransportType.HTTP2)
        uuid, request = client.login("wordpass")

        conf = h2.config.H2Configuration(client_side=True)

        server = h2.connection.H2Connection(conf)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())

        events = server.receive_data(request)
        # assert events[0].headers == []

        client.receive(self.login_response(1, frame_factory))
        response = client.next_response()

        assert isinstance(response, LoginResponse)
        assert response.uuid == uuid

        uuid, request = client.sync()

        events = server.receive_data(request)

        client.receive(self.sync_response(3, frame_factory))
        response = client.next_response()

        assert isinstance(response, SyncRepsponse)
        assert response.uuid == uuid

        sync_uuid, request = client.sync()

        server.receive_data(request)

        content = {
            "body": "test",
            "msgtype": "m.text"
        }

        send_uuid, send_request = client.room_send(
            "!test:localhost",
            "m.room.message",
            content
        )
