import sys
import json
import pytest

from nio import LoginResponse, SyncResponse, LoginError, LocalProtocolError

if sys.version_info >= (3, 5):
    import asyncio


@pytest.mark.skipif(sys.version_info < (3, 5), reason="Python 3 specific asyncio tests")
class TestClass(object):
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    @property
    def login_response(self):
        return self._load_response("tests/data/login_response.json")

    @property
    def sync_response(self):
        return self._load_response("tests/data/sync.json")

    def test_login(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        resp = loop.run_until_complete(async_client.login("wordpass"))

        assert isinstance(resp, LoginResponse)
        assert async_client.access_token
        assert async_client.logged_in

    def test_failed_login(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        assert not async_client.access_token
        assert not async_client.logged_in

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=400,
            body=""
        )
        resp = loop.run_until_complete(async_client.login("wordpass"))
        assert isinstance(resp, LoginError)
        assert not async_client.logged_in

        assert async_client.client_session
        async_client.close()
        loop.run_until_complete(async_client.close())
        assert not async_client.client_session

    def test_sync(self, async_client, aioresponse):
        loop = asyncio.get_event_loop()

        aioresponse.post(
            "https://example.org/_matrix/client/r0/login",
            status=200,
            payload=self.login_response
        )
        aioresponse.get(
            "https://example.org/_matrix/client/r0/sync?access_token=abc123",
            status=200,
            payload=self.sync_response
        )
        with pytest.raises(LocalProtocolError):
            resp2 = loop.run_until_complete(async_client.sync())

        resp = loop.run_until_complete(async_client.login("wordpass"))
        resp2 = loop.run_until_complete(async_client.sync())

        assert isinstance(resp, LoginResponse)
        assert isinstance(resp2, SyncResponse)
