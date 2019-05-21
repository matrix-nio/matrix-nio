# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import pdb

from nio.events import (BadEvent, OlmEvent, PowerLevelsEvent, RedactedEvent,
                        RedactionEvent, RoomAliasEvent, RoomCreateEvent,
                        RoomGuestAccessEvent, RoomHistoryVisibilityEvent,
                        RoomJoinRulesEvent, RoomMemberEvent, RoomMessageEmote,
                        RoomMessageNotice, RoomMessageText, RoomNameEvent,
                        RoomTopicEvent, ToDeviceEvent, UnknownBadEvent)


class TestClass(object):
    @staticmethod
    def _load_response(filename):
        # type: (str) -> Dict[Any, Any]
        with open(filename) as f:
            return json.loads(f.read(), encoding="utf-8")

    def test_redacted_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redacted.json")
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, RedactedEvent)

    def test_malformed_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redacted_invalid.json")
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, BadEvent)

    def test_create_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/create.json")
        event = RoomCreateEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomCreateEvent)

    def test_guest_access_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/guest_access.json")
        event = RoomGuestAccessEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomGuestAccessEvent)

    def test_join_rules_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/join_rules.json")
        event = RoomJoinRulesEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomJoinRulesEvent)

    def test_history_visibility_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/history_visibility.json")
        event = RoomHistoryVisibilityEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomHistoryVisibilityEvent)

    def test_topic_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/topic.json")
        event = RoomTopicEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomTopicEvent)

    def test_name_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/name.json")
        event = RoomNameEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomNameEvent)

    def test_alias_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/alias.json")
        event = RoomAliasEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomAliasEvent)

    def test_message_text(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/message_text.json")
        event = RoomMessageText.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageText)

    def test_message_emote(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/message_emote.json")
        event = RoomMessageEmote.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageEmote)

    def test_message_notice(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/message_notice.json")
        event = RoomMessageNotice.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageNotice)

    def test_power_levels(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/power_levels.json")
        event = PowerLevelsEvent.from_dict(parsed_dict)
        assert isinstance(event, PowerLevelsEvent)

    def test_membership(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/member.json")
        event = RoomMemberEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomMemberEvent)

    def test_redaction(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redaction.json")
        event = RedactionEvent.from_dict(parsed_dict)
        assert isinstance(event, RedactionEvent)

    def test_olm_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/olm_event.json")
        event = ToDeviceEvent.parse_event(parsed_dict)
        assert isinstance(event, OlmEvent)

    def test_empty_event(self):
        parsed_dict = {}
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, UnknownBadEvent)
