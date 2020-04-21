# -*- coding: utf-8 -*-

import pytest

import nio.event_builders as builders


class TestClass:
    def test_base_class(self):
        with pytest.raises(NotImplementedError):
            builders.EventBuilder().as_dict()

    def test_enable_encryption(self):
        event = builders.EnableEncryptionBuilder(
            algorithm="test", rotation_ms=9801, rotation_msgs=101
        ).as_dict()

        assert event == {
            "type":      "m.room.encryption",
            "state_key": "",
            "content":   {
                "algorithm":            "test",
                "rotation_period_ms":   9801,
                "rotation_period_msgs": 101,
            },
        }

    def test_change_name(self):
        event = builders.ChangeNameBuilder("foo").as_dict()
        assert event == {
            "type":      "m.room.name",
            "state_key": "",
            "content":   {"name": "foo"},
        }

        with pytest.raises(ValueError):
            builders.ChangeNameBuilder("TooLongName" * 256)


    def test_change_topic(self):
        event = builders.ChangeTopicBuilder("Lorem ipsum").as_dict()
        assert event == {
            "type":      "m.room.topic",
            "state_key": "",
            "content":   {"topic": "Lorem ipsum"},
        }

    def test_change_join_rules(self):
        event = builders.ChangeJoinRulesBuilder("invite").as_dict()
        assert event == {
            "type":      "m.room.join_rules",
            "state_key": "",
            "content":   {"join_rule": "invite"},
        }

    def test_change_guest_access(self):
        event = builders.ChangeGuestAccessBuilder("can_join").as_dict()
        assert event == {
            "type":      "m.room.guest_access",
            "state_key": "",
            "content":   {"guest_access": "can_join"},
        }

    def test_change_history_visibility(self):
        event = builders.ChangeHistoryVisibilityBuilder("joined").as_dict()
        assert event == {
            "type":      "m.room.history_visibility",
            "state_key": "",
            "content":   {"history_visibility": "joined"},
        }
