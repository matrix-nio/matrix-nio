# Copyright © 2021 Famedly GmbH
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


from nio.api import MATRIX_API_PATH_V3, Api


class TestClass:
    def test_profile_get(self) -> None:
        """Test that profile_get returns the HTTP path for the request."""
        api = Api()
        encode_pairs = [
            # a normal username
            ("@bob:example.com", "%40bob%3Aexample.com"),
            # an irregular but legal username
            (
                "@a-z0-9._=-/:example.com",
                "%40a-z0-9._%3D-%2F%3Aexample.com",
                # Why include this? https://github.com/poljar/matrix-nio/issues/211
                # There were issues with a username that included slashes, which is
                # legal by the standard: https://matrix.org/docs/spec/appendices#user-identifiers
            ),
        ]
        for unencoded, encoded in encode_pairs:
            expected_path = f"{MATRIX_API_PATH_V3}/profile/{encoded}"
            _method, actual_path = api.profile_get(unencoded)
            assert actual_path == expected_path

    def test_profile_get_authed(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        user_id = "@bob:example.com"
        encoded = "%40bob%3Aexample.com"
        token = "SECRET_TOKEN"

        expected = f"{MATRIX_API_PATH_V3}/profile/{encoded}?access_token={token}"
        resp = api.profile_get(user_id, token)

        assert resp == ("GET", expected)

    def test_delete_room_alias(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        room_alias = "#room:example.com"
        encoded = "%23room%3Aexample.com"
        token = "SECRET_TOKEN"

        expected = f"{MATRIX_API_PATH_V3}/directory/room/{encoded}?access_token={token}"
        resp = api.delete_room_alias(token, room_alias)

        assert resp == ("DELETE", expected)

    def test_put_room_alias(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        room_alias = "#room:example.com"
        encoded = "%23room%3Aexample.com"
        room_id = "!room_id:example.com"
        token = "SECRET_TOKEN"

        expected_path = (
            f"{MATRIX_API_PATH_V3}/directory/room/{encoded}?access_token={token}"
        )
        expected_data = '{"room_id":"!room_id:example.com"}'
        resp = api.put_room_alias(token, room_alias, room_id)

        assert resp == ("PUT", expected_path, expected_data)

    def test_mxc_to_http_server_name(self) -> None:
        """The whole ``server_name`` of an mxc URI must survive the conversion.

        https://spec.matrix.org/v1.11/appendices/#server-name defines
        ``server_name = hostname [ ":" port ]`` with
        ``hostname = IPv4address / "[" IPv6address "]" / dns-name``, and states
        that server names are case sensitive.  So the port, the brackets around
        an IPv6 literal and the original casing are all part of the identifier
        the media endpoint is addressed with.
        """
        api = Api()
        cases = [
            (
                "mxc://example.org/abc123",
                "https://example.org/_matrix/client/v1/media/download/example.org/abc123",
            ),
            (
                "mxc://localhost:8008/abc123",
                "https://localhost:8008/_matrix/client/v1/media/download/localhost:8008/abc123",
            ),
            (
                "mxc://[::1]:8448/abc123",
                "https://[::1]:8448/_matrix/client/v1/media/download/[::1]:8448/abc123",
            ),
            (
                "mxc://Example.ORG/abc123",
                "https://Example.ORG/_matrix/client/v1/media/download/Example.ORG/abc123",
            ),
        ]
        for mxc, expected in cases:
            assert api.mxc_to_http(mxc) == expected

    def test_mxc_to_http_server_name_authenticated(self) -> None:
        """Same as above, for the authenticated (percent-encoded) code path."""
        api = Api()
        homeserver = "https://chat.example.org"
        cases = [
            (
                "mxc://example.org/abc123",
                "/_matrix/client/v1/media/download/example.org/abc123",
            ),
            (
                "mxc://localhost:8008/abc123",
                "/_matrix/client/v1/media/download/localhost%3A8008/abc123",
            ),
            (
                "mxc://[::1]:8448/abc123",
                "/_matrix/client/v1/media/download/%5B%3A%3A1%5D%3A8448/abc123",
            ),
            (
                "mxc://Example.ORG/abc123",
                "/_matrix/client/v1/media/download/Example.ORG/abc123",
            ),
        ]
        for mxc, expected_path in cases:
            assert api.mxc_to_http(mxc, homeserver, access_token="TOKEN") == (
                f"{homeserver}{expected_path}?access_token=TOKEN"
            )

    def test_encrypted_mxc_to_plumb_server_name(self) -> None:
        """``encrypted_mxc_to_plumb`` must keep the server name intact too."""
        api = Api()
        plumb = api.encrypted_mxc_to_plumb(
            "mxc://localhost:8008/abc123", "KEY", "HASH", "IV"
        )
        assert plumb == (
            "emxc://localhost:8008/_matrix/media/v3/download/localhost:8008/abc123"
            "?key=KEY&hash=HASH&iv=IV"
        )
