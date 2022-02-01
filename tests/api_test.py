# -*- coding: utf-8 -*-

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

from urllib.parse import urlencode
from nio.api import Api


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
                "%40a-z0-9._%3D-%2F%3Aexample.com"
                # Why include this? https://github.com/poljar/matrix-nio/issues/211
                # There were issues with a username that included slashes, which is
                # legal by the standard: https://matrix.org/docs/spec/appendices#user-identifiers
            ),
        ]
        for unencoded, encoded in encode_pairs:
            expected_path = f"/_matrix/client/r0/profile/{encoded}"
            (method, actual_path) = api.profile_get(unencoded)
            assert actual_path == expected_path

    def test_profile_get_authed(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        user_id = "@bob:example.com"
        encoded = "%40bob%3Aexample.com"
        token = "SECRET_TOKEN"

        expected = f"/_matrix/client/r0/profile/{encoded}?access_token={token}"
        resp = api.profile_get(user_id, token)

        assert resp == ('GET', expected)

    def test_delete_room_alias(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        room_alias = "#room:example.com"
        encoded = "%23room%3Aexample.com"
        token = "SECRET_TOKEN"

        expected = f"/_matrix/client/r0/directory/room/{encoded}?access_token={token}"
        resp = api.delete_room_alias(token, room_alias)

        assert resp == ('DELETE', expected)

    def test_put_room_alias(self) -> None:
        """Test that profile_get sets access_token in query param"""
        api = Api()
        room_alias = "#room:example.com"
        encoded = "%23room%3Aexample.com"
        room_id = "!room_id:example.com"
        token = "SECRET_TOKEN"

        expected_path = f"/_matrix/client/r0/directory/room/{encoded}?access_token={token}"
        expected_data = '{"room_id":"!room_id:example.com"}'
        resp = api.put_room_alias(token, room_alias, room_id)

        assert resp == ('PUT', expected_path, expected_data)