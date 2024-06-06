from __future__ import annotations

from pathlib import Path

from nio.client import HttpClient


class TestClass:

    def test_503(self):
        client = HttpClient("localhost", "example")
        client.connect()
        client.login("test")
        transport_response = Path("tests/data/http_503.txt").read_bytes()
        client.receive(transport_response)
        response = client.next_response()
        assert response.status_code == 503

    def test_502(self):
        client = HttpClient("localhost", "example")
        client.connect()
        client.login("test")
        transport_response = Path("tests/data/http_502.txt").read_bytes()
        client.receive(transport_response)
        response = client.next_response()
        assert response.status_code == 502
