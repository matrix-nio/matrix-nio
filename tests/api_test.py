# -*- coding: utf-8 -*-

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