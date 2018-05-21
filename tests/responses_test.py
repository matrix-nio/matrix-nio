# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json

from nio.responses import ErrorResponse, LoginResponse


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def test_login_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_response.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, LoginResponse)

    def test_login_failure_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_response_error.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, ErrorResponse)

    def test_login_failure_format(self):
        parsed_dict = TestClass._load_response(
            "tests/data/login_invalid_format.json")
        response = LoginResponse.from_dict(parsed_dict)
        assert isinstance(response, ErrorResponse)
