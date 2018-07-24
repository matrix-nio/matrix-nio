# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from nio.client import HttpClient
from nio.http import TransportResponse


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename, "rb") as f:
            return f.read()

    def test_503(self):
        client = HttpClient("localhost", "example")
        client.connect()
        client.login("test")
        transport_response = self._load_response("tests/data/http_503.txt")
        client.receive(transport_response)
        response = client.next_response()
        assert response.status_code == 503

    def test_502(self):
        client = HttpClient("localhost", "example")
        client.connect()
        client.login("test")
        transport_response = self._load_response("tests/data/http_502.txt")
        client.receive(transport_response)
        response = client.next_response()
        assert response.status_code == 502
