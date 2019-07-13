# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import pdb

from nio.events import (BadEvent, OlmEvent, PowerLevelsEvent, RedactedEvent,
                        RedactionEvent, RoomAliasEvent, RoomCreateEvent,
                        RoomGuestAccessEvent, RoomHistoryVisibilityEvent,
                        RoomJoinRulesEvent, RoomMemberEvent, RoomMessageEmote,
                        RoomMessageNotice, RoomMessageText, RoomNameEvent,
                        RoomTopicEvent, RoomAvatarEvent, ToDeviceEvent,
                        UnknownBadEvent, Event, RoomEncryptionEvent,
                        InviteEvent, RoomKeyEvent, ForwardedRoomKeyEvent,
                        MegolmEvent, UnknownEncryptedEvent, InviteMemberEvent,
                        InviteAliasEvent, InviteNameEvent, EphemeralEvent,
                        TypingNoticeEvent, AccountDataEvent,
                        UnknownAccountDataEvent, FullyReadEvent, CallEvent,
                        CallAnswerEvent, CallHangupEvent, CallInviteEvent,
                        CallCandidatesEvent, KeyVerificationStart,
                        KeyVerificationAccept, KeyVerificationCancel,
                        KeyVerificationKey, KeyVerificationMac)


class TestClass(object):
    @staticmethod
    def _load_response(filename):
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

    def test_room_avatar_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/room_avatar.json")
        event = RoomAvatarEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomAvatarEvent)

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

    def test_empty_event(self):
        parsed_dict = {}
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, UnknownBadEvent)

    def test_room_encryption(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/room_encryption.json")
        event = Event.parse_event(parsed_dict)
        assert isinstance(event, RoomEncryptionEvent)

    def test_room_key(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/room_key.json")
        event = RoomKeyEvent.from_dict(
            parsed_dict,
            "@alice:example.org",
            "alice_key"
        )
        assert isinstance(event, RoomKeyEvent)

    def test_forwarded_room_key(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/forwarded_room_key.json")
        event = ForwardedRoomKeyEvent.from_dict(
            parsed_dict,
            "@alice:example.org",
            "alice_key"
        )
        assert isinstance(event, RoomKeyEvent)


    def test_invalid_state_event(self):
        for event_type, event_file in [
                ("m.room.create", "create.json"),
                ("m.room.guest_access", "guest_access.json"),
                ("m.room.join_rules", "join_rules.json"),
                ("m.room.history_visibility", "history_visibility.json"),
                ("m.room.member", "member.json"),
                ("m.room.canonical_alias", "alias.json"),
                ("m.room.name", "name.json"),
                ("m.room.topic", "topic.json"),
                ("m.room.avatar", "room_avatar.json"),
                ("m.room.power_levels", "power_levels.json"),
                ("m.room.encryption", "room_encryption.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            parsed_dict.pop("state_key")

            event = Event.parse_event(parsed_dict)

            assert isinstance(event, BadEvent)
            assert event.source["type"] == event_type

    def test_invalid_invite_state_events(self):
        for event_type, event_file in [
                ("m.room.member", "member.json"),
                ("m.room.canonical_alias", "alias.json"),
                ("m.room.name", "name.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            parsed_dict.pop("state_key")

            event = InviteEvent.parse_event(parsed_dict)

            assert isinstance(event, BadEvent)
            assert event.source["type"] == event_type

        for event_type, event_file in [
                ("m.room.member", "member.json"),
                ("m.room.canonical_alias", "alias.json"),
                ("m.room.name", "name.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            parsed_dict.pop("type")

            event = InviteEvent.parse_event(parsed_dict)
            assert not event

    def test_invite_events(self):
        for event_type, event_file in [
                (InviteMemberEvent, "member.json"),
                (InviteAliasEvent, "alias.json"),
                (InviteNameEvent, "name.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            event = InviteEvent.parse_event(parsed_dict)
            assert isinstance(event, event_type)

    def test_megolm_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/megolm.json")
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, MegolmEvent)

        parsed_dict["content"]["algorithm"] = "m.megolm.unknown"
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, UnknownEncryptedEvent)

    def test_olm_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/olm.json")
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert isinstance(event, OlmEvent)

        parsed_dict["content"]["algorithm"] = "m.megolm.unknown"
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert not event

    def test_ephemeral_event(self):
        event = EphemeralEvent.parse_event({})

        assert not event

        event = EphemeralEvent.parse_event({
            "type": "m.unknown",
            "content": {}
        })

        assert not event

    def test_typing_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/typing.json")
        event = EphemeralEvent.parse_event(parsed_dict)

        assert isinstance(event, TypingNoticeEvent)

        assert "@bob:example.com" in event.users

    def test_account_data_event(self):
        event = AccountDataEvent.parse_event({})

        assert isinstance(event, UnknownBadEvent)

        event = AccountDataEvent.parse_event({
            "type": "m.unknown",
            "content": {}
        })

        assert isinstance(event, UnknownAccountDataEvent)

    def test_fully_read_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/fully_read.json")
        event = AccountDataEvent.parse_event(parsed_dict)

        assert isinstance(event, FullyReadEvent)

    def test_invalid_call_events(self):
        for _, event_file in [
                (CallInviteEvent, "call_invite.json"),
                (CallAnswerEvent, "call_answer.json"),
                (CallCandidatesEvent, "call_candidates.json"),
                (CallHangupEvent, "call_hangup.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            parsed_dict["content"].pop("call_id")
            event = CallEvent.parse_event(parsed_dict)
            assert isinstance(event, BadEvent)

    def test_call_events(self):
        for event_type, event_file in [
                (CallInviteEvent, "call_invite.json"),
                (CallAnswerEvent, "call_answer.json"),
                (CallCandidatesEvent, "call_candidates.json"),
                (CallHangupEvent, "call_hangup.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            event = CallEvent.parse_event(parsed_dict)
            assert isinstance(event, event_type)

    def test_key_verification_events(self):
        for event_type, event_file in [
                (KeyVerificationStart, "key_start.json"),
                (KeyVerificationAccept, "key_accept.json"),
                (KeyVerificationKey, "key_key.json"),
                (KeyVerificationMac, "key_mac.json"),
                (KeyVerificationCancel, "key_cancel.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            event = ToDeviceEvent.parse_event(parsed_dict)
            assert isinstance(event, event_type)

    def test_invalid_key_verification(self):
        for _, event_file in [
                (KeyVerificationStart, "key_start.json"),
                (KeyVerificationAccept, "key_accept.json"),
                (KeyVerificationKey, "key_key.json"),
                (KeyVerificationMac, "key_mac.json"),
                (KeyVerificationCancel, "key_cancel.json"),
        ]:
            parsed_dict = TestClass._load_response(
                "tests/data/events/{}".format(event_file)
            )
            parsed_dict["content"].pop("transaction_id")
            event = ToDeviceEvent.parse_event(parsed_dict)
            assert isinstance(event, UnknownBadEvent)

    def test_invalid_room_event(self):
        event = Event.parse_event({"type": "m.unknown"})

        assert isinstance(event, UnknownBadEvent)

    def test_redacted_state_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redacted_state.json")
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, RedactedEvent)
