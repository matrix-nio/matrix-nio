# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import h2

from nio.client import HttpClient, TransportType, RequestInfo, RequestType
from nio.http import TransportResponse, Http2Response
from nio.responses import LoginResponse, SyncResponse
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

    def test_client_lag(self, frame_factory):
        client = HttpClient("localhost", "example")
        client.connect(TransportType.HTTP2)
        response = Http2Response()
        response.send_time = 0
        response.receive_time = 30
        response.timeout = 25 * 1000
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

        assert isinstance(response, SyncResponse)
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
