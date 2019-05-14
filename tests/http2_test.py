# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import h2
import pytest

from nio.client import HttpClient, RequestInfo, TransportType
from nio.exceptions import LocalProtocolError
from nio.http import Http2Response
from nio.responses import LoginResponse, SyncResponse


class TestClass(object):
    example_response_headers = [
        (':status', '200'),
        ('server', 'fake-serv/0.1.0')
    ]

    @staticmethod
    def _load_response(filename):
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

        response2 = Http2Response()
        response2.send_time = 0
        response2.receive_time = 31
        response2.timeout = 25 * 1000

        client.connection._responses[response.uuid] = response
        client.connection._responses[response2.uuid] = response2
        typed_response = RequestInfo("sync", 25 * 1000)
        client.requests_made[response.uuid] = typed_response

        assert client.lag == 6

    def test_client_local_error(self, frame_factory):
        client = HttpClient("localhost", "example")

        with pytest.raises(LocalProtocolError):
            uuid, request = client.login("wordpass")

        client.connect(TransportType.HTTP2)
        uuid, request = client.login("wordpass")

        with pytest.raises(LocalProtocolError):
            uuid, request = client.sync()

        client.receive(self.login_response(1, frame_factory))
        client.next_response()
        uuid, request = client.sync()

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

    def test_frame_splitting(self, frame_factory):
        client = HttpClient("localhost", "example")
        data = client.connect(TransportType.HTTP2)
        client.connection._connection.outbound_flow_control_window = 5
        uuid, request = client.login("wordpass")

        assert client.connection._data_to_send

        to_send = data + request

        while to_send:
            f = frame_factory.build_window_update_frame(
                stream_id=0,
                increment=5,
            )
            client.receive(f.serialize())
            to_send = client.data_to_send()

        assert not client.connection._data_to_send
