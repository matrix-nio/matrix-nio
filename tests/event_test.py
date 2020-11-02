# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import json
import pdb

from nio.events import (
    BadEvent,
    OlmEvent,
    PowerLevelsEvent,
    RedactedEvent,
    RedactionEvent,
    RoomAliasEvent,
    RoomCreateEvent,
    RoomGuestAccessEvent,
    RoomHistoryVisibilityEvent,
    RoomJoinRulesEvent,
    RoomMemberEvent,
    RoomMessageEmote,
    RoomMessageNotice,
    RoomMessageText,
    RoomNameEvent,
    RoomTopicEvent,
    RoomAvatarEvent,
    ToDeviceEvent,
    UnknownBadEvent,
    Event,
    RoomEncryptionEvent,
    InviteEvent,
    RoomKeyEvent,
    ForwardedRoomKeyEvent,
    MegolmEvent,
    UnknownEncryptedEvent,
    InviteMemberEvent,
    InviteAliasEvent,
    InviteNameEvent,
    EphemeralEvent,
    TypingNoticeEvent,
    Receipt,
    ReceiptEvent,
    AccountDataEvent,
    UnknownAccountDataEvent,
    FullyReadEvent,
    CallEvent,
    CallAnswerEvent,
    CallHangupEvent,
    CallInviteEvent,
    CallCandidatesEvent,
    KeyVerificationStart,
    KeyVerificationAccept,
    KeyVerificationCancel,
    RoomEncryptedImage,
    KeyVerificationKey,
    KeyVerificationMac,
    TagEvent,
    DummyEvent,
    RoomKeyRequest,
    RoomKeyRequestCancellation,
    PushRulesEvent,
)


class TestClass:
    @staticmethod
    def _load_response(filename):
        with open(filename) as f:
            return json.loads(f.read())

    def test_redacted_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/redacted.json")
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, RedactedEvent)

    def test_malformed_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/redacted_invalid.json"
        )
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, BadEvent)

    def test_create_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/create.json")
        event = RoomCreateEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomCreateEvent)

    def test_guest_access_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/guest_access.json")
        event = RoomGuestAccessEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomGuestAccessEvent)

    def test_join_rules_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/join_rules.json")
        event = RoomJoinRulesEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomJoinRulesEvent)

    def test_history_visibility_event(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/history_visibility.json"
        )
        event = RoomHistoryVisibilityEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomHistoryVisibilityEvent)

    def test_topic_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/topic.json")
        event = RoomTopicEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomTopicEvent)

    def test_room_avatar_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/room_avatar.json")
        event = RoomAvatarEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomAvatarEvent)

    def test_room_avatar_event_no_url(self):
        parsed_dict = TestClass._load_response("tests/data/events/room_avatar.json")
        parsed_dict["content"].pop("url")
        event = RoomAvatarEvent.from_dict(parsed_dict)
        assert isinstance(event, BadEvent)

    def test_tag_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/tag.json")
        event = AccountDataEvent.parse_event(parsed_dict)
        assert isinstance(event, TagEvent)

    def test_name_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/name.json")
        event = RoomNameEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomNameEvent)

    def test_alias_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/alias.json")
        event = RoomAliasEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomAliasEvent)

    def test_message_text(self):
        parsed_dict = TestClass._load_response("tests/data/events/message_text.json")
        event = RoomMessageText.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageText)

    def test_message_emote(self):
        parsed_dict = TestClass._load_response("tests/data/events/message_emote.json")
        event = RoomMessageEmote.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageEmote)

    def test_message_notice(self):
        parsed_dict = TestClass._load_response("tests/data/events/message_notice.json")
        event = RoomMessageNotice.from_dict(parsed_dict)
        assert isinstance(event, RoomMessageNotice)

    def test_power_levels(self):
        parsed_dict = TestClass._load_response("tests/data/events/power_levels.json")
        event = PowerLevelsEvent.from_dict(parsed_dict)
        assert isinstance(event, PowerLevelsEvent)

        levels = event.power_levels
        admin = "@example:localhost"
        mod = "@alice:localhost"
        higher_user = "@carol:localhost"
        user = "@bob:localhost"

        assert levels.get_state_event_required_level("m.room.name") == 50
        assert levels.get_state_event_required_level("m.room.undefined") == 50
        assert levels.get_message_event_required_level("m.room.message") == 25
        assert levels.get_message_event_required_level("m.room.undefined") == 0
        assert levels.get_notification_required_level("room") == 60
        assert levels.get_notification_required_level("non_existant") == 50

        assert levels.get_user_level(admin) == 100
        assert levels.get_user_level(user) == 0

        assert levels.can_user_send_state(admin, "m.room.name") is True
        assert levels.can_user_send_state(user, "m.room.name") is False
        assert levels.can_user_send_message(admin) is True
        assert levels.can_user_send_message(user, "m.room.message") is False

        assert levels.can_user_invite(admin) is True
        assert levels.can_user_invite(user) is True

        assert levels.can_user_kick(admin) is True
        assert levels.can_user_kick(user) is False
        assert levels.can_user_kick(admin, admin) is False
        assert levels.can_user_kick(admin, mod) is True
        assert levels.can_user_kick(mod, admin) is False
        assert levels.can_user_kick(mod, higher_user) is True
        assert levels.can_user_kick(higher_user, user) is False

        assert levels.can_user_ban(admin) is True
        assert levels.can_user_ban(user) is False
        assert levels.can_user_ban(admin, admin) is False
        assert levels.can_user_ban(admin, mod) is True
        assert levels.can_user_ban(mod, admin) is False
        assert levels.can_user_ban(mod, higher_user) is True
        assert levels.can_user_ban(higher_user, user) is False

        assert levels.can_user_redact(admin) is True
        assert levels.can_user_redact(user) is False

        assert levels.can_user_notify(admin, "room") is True
        assert levels.can_user_notify(mod, "room") is False

    def test_membership(self):
        parsed_dict = TestClass._load_response("tests/data/events/member.json")
        event = RoomMemberEvent.from_dict(parsed_dict)
        assert isinstance(event, RoomMemberEvent)

    def test_redaction(self):
        parsed_dict = TestClass._load_response("tests/data/events/redaction.json")
        event = RedactionEvent.from_dict(parsed_dict)
        assert isinstance(event, RedactionEvent)

    def test_empty_event(self):
        parsed_dict = {}
        response = RedactedEvent.from_dict(parsed_dict)
        assert isinstance(response, UnknownBadEvent)

    def test_room_encryption(self):
        parsed_dict = TestClass._load_response("tests/data/events/room_encryption.json")
        event = Event.parse_event(parsed_dict)
        assert isinstance(event, RoomEncryptionEvent)

    def test_room_key(self):
        parsed_dict = TestClass._load_response("tests/data/events/room_key.json")
        event = RoomKeyEvent.from_dict(parsed_dict, "@alice:example.org", "alice_key")
        assert isinstance(event, RoomKeyEvent)

    def test_forwarded_room_key(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/forwarded_room_key.json"
        )
        event = ForwardedRoomKeyEvent.from_dict(
            parsed_dict, "@alice:example.org", "alice_key"
        )
        assert isinstance(event, ForwardedRoomKeyEvent)

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
        parsed_dict = TestClass._load_response("tests/data/events/megolm.json")
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, MegolmEvent)

        parsed_dict["content"]["algorithm"] = "m.megolm.unknown"
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, UnknownEncryptedEvent)

    def test_olm_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/olm.json")
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert isinstance(event, OlmEvent)

        parsed_dict["content"]["algorithm"] = "m.megolm.unknown"
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert not event

    def test_ephemeral_event(self):
        event = EphemeralEvent.parse_event({})

        assert not event

        event = EphemeralEvent.parse_event({"type": "m.unknown", "content": {}})

        assert not event

    def test_typing_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/typing.json")
        event = EphemeralEvent.parse_event(parsed_dict)

        assert isinstance(event, TypingNoticeEvent)

        assert "@bob:example.com" in event.users

    def test_read_receipt_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/receipt.json")
        event = EphemeralEvent.parse_event(parsed_dict)

        # Warning: this is directly tied to the above file; any changes below
        # need to be reflected there too.
        receipt = Receipt(
            "$152037280074GZeOm:localhost",
            "m.read",
            "@bob:example.com",
            1520372804619
        )

        assert isinstance(event, ReceiptEvent)
        assert receipt in event.receipts

    def test_read_receipt_event_bad_ts(self):
        """Test reading an m_receipt event that has malformed data for one user.

        @alice:example.com is a user using Synapse pre 0.99.3 with a
        timestamp bug. We want to ignore her malformed value without losing
        the receipt data from @bob:example.com
        """
        parsed_dict = TestClass._load_response("tests/data/events/receipt_invalid.json")
        event = EphemeralEvent.parse_event(parsed_dict)

        # Warning: this is directly tied to the above file; any changes below
        # need to be reflected there too.
        receipt = Receipt(
            "$152037280074GZeOm:localhost",
            "m.read",
            "@bob:example.com",
            1520372804619
        )

        assert isinstance(event, ReceiptEvent)
        assert receipt in event.receipts


    def test_account_data_event(self):
        event = AccountDataEvent.parse_event({})

        assert isinstance(event, UnknownBadEvent)

        event = AccountDataEvent.parse_event({"type": "m.unknown", "content": {}})

        assert isinstance(event, UnknownAccountDataEvent)

    def test_fully_read_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/fully_read.json")
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
        parsed_dict = TestClass._load_response("tests/data/events/redacted_state.json")
        event = Event.parse_event(parsed_dict)

        assert isinstance(event, RedactedEvent)

    def test_dummy_event(self):
        parsed_dict = TestClass._load_response("tests/data/events/dummy.json")
        event = DummyEvent.from_dict(parsed_dict, "@alice:example.org", "alice_key")

        assert isinstance(event, DummyEvent)

    def test_room_key_request(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/room_key_request.json"
        )
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert isinstance(event, RoomKeyRequest)
        assert event.room_id is not None

        parsed_dict = TestClass._load_response(
            "tests/data/events/room_key_request_cancel.json"
        )
        event = ToDeviceEvent.parse_event(parsed_dict)

        assert isinstance(event, RoomKeyRequestCancellation)

    def test_encrypted_media_thumbnails(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/room_encrypted_image.json"
        )

        event = Event.parse_decrypted_event(parsed_dict)

        assert isinstance(event, RoomEncryptedImage)
        assert event.thumbnail_url
        assert event.thumbnail_key
        assert event.thumbnail_hashes
        assert event.thumbnail_iv

    def test_event_flattening(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/to_flatten.json",
        )

        event = Event.from_dict(parsed_dict)
        assert event.flattened() == {
            "content.body": "foo",
            "content.m.dotted.key": "bar",
            "event_id": "!test:example.org",
            "origin_server_ts": 0,
            "sender": "@alice:example.org",
            "type": "m.flatten_test",
        }

    def test_pushrules_parsing(self):
        parsed_dict = TestClass._load_response(
            "tests/data/events/push_rules.json",
        )
        parsed_rule = parsed_dict["content"]["global"]["override"][0]

        event = PushRulesEvent.from_dict(parsed_dict)
        assert isinstance(event, PushRulesEvent)
        assert bool(event) is True
        rule = event.global_rules.override[0]

        for i, action in enumerate(rule.actions):
            assert action.as_value == parsed_rule["actions"][i]

        for i, condition in enumerate(rule.conditions):
            assert condition.as_value == parsed_rule["conditions"][i]
