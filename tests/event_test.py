# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json

from nio.responses import RedactedEvent


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def test_login_parse(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redacted.json")
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, RedactedEvent)
