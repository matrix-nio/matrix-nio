# -*- coding: utf-8 -*-

from nio.event_builders import EnableEncryptionBuilder


class TestClass(object):
    def test_enable_encryption(self):
        event = EnableEncryptionBuilder(
            algorithm="test", rotation_ms=9801, rotation_msgs=101
        ).as_dict()

        assert event["type"]                            == "m.room.encryption"
        assert event["content"]["algorithm"]            == "test"
        assert event["content"]["rotation_period_ms"]   == 9801
        assert event["content"]["rotation_period_msgs"] == 101
