# -*- coding: utf-8 -*-

# Copyright © 2018-2019 Damir Jelić <poljar@termina.org.uk>
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

from __future__ import unicode_literals

import time
from builtins import super
from typing import Any, Dict, Optional, Union

import attr

from ..schemas import Schemas
from .encrypted_events import RoomEncryptedEvent
from .misc import BadEventType, UnknownBadEvent, validate_or_badevent, verify


@attr.s
class Event(object):
    source = attr.ib()

    event_id = attr.ib(init=False)
    sender = attr.ib(init=False)
    server_timestamp = attr.ib(init=False)

    decrypted = attr.ib(default=False, init=False)
    verified = attr.ib(default=False, init=False)
    sender_key = attr.ib(default=None, init=False)  # type: Optional[str]
    session_id = attr.ib(default=None, init=False)  # type: Optional[str]
    transaction_id = attr.ib(default=None, init=False)  # type: Optional[str]

    def __attrs_post_init__(self):
        self.event_id = self.source["event_id"]
        self.sender = self.source["sender"]
        self.server_timestamp = self.source["origin_server_ts"]

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[Event, BadEventType]
        return cls(parsed_dict)

    @classmethod
    def parse_event(
        cls,
        event_dict,  # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[Event, BadEventType]
        if "unsigned" in event_dict:
            if "redacted_because" in event_dict["unsigned"]:
                return RedactedEvent.from_dict(event_dict)

        if event_dict["type"] == "m.room.message":
            return RoomMessage.parse_event(event_dict)
        elif event_dict["type"] == "m.room.create":
            return RoomCreateEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.guest_access":
            return RoomGuestAccessEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.join_rules":
            return RoomJoinRulesEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.history_visibility":
            return RoomHistoryVisibilityEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.member":
            return RoomMemberEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.canonical_alias":
            return RoomAliasEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.name":
            return RoomNameEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.topic":
            return RoomTopicEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.power_levels":
            return PowerLevelsEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encryption":
            return RoomEncryptionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.redaction":
            return RedactionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encrypted":
            return RoomEncryptedEvent.parse_event(event_dict)
        elif event_dict["type"].startswith("m.call"):
            return CallEvent.parse_event(event_dict)

        return UnknownEvent.from_dict(event_dict)


@attr.s
class UnknownEvent(Event):
    type = attr.ib()

    @classmethod
    def from_dict(cls, event_dict):
        return cls(
            event_dict,
            event_dict["type"],
        )


@attr.s
class EncryptedEvent(Event):
    @classmethod
    def parse_event(
        cls,
        event_dict,  # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[Event, BadEventType]
        if "unsigned" in event_dict:
            if "redacted_because" in event_dict["unsigned"]:
                return RedactedEvent.from_dict(event_dict)

        if event_dict["type"] == "m.room.message":
            return RoomEncryptedMessage.parse_event(event_dict)

        return super().parse_event(event_dict)


@attr.s
class CallEvent(Event):
    call_id = attr.ib()
    version = attr.ib()

    @staticmethod
    def parse_event(event_dict):
        if event_dict["type"] == "m.call.candidates":
            event = CallCandidatesEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.invite":
            event = CallInviteEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.answer":
            event = CallAnswerEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.hangup":
            event = CallHangupEvent.from_dict(event_dict)
        else:
            event = UnknownEvent.from_dict(event_dict)

        return event


@attr.s
class CallCandidatesEvent(CallEvent):
    candidates = attr.ib()

    @classmethod
    @verify(Schemas.call_candidates)
    def from_dict(cls, event_dict):
        content = event_dict.pop("content")
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["candidates"],
        )


@attr.s
class CallInviteEvent(CallEvent):
    lifetime = attr.ib()
    offer = attr.ib()

    @property
    def expired(self):
        """Property marking if the invite event expired."""
        now = time.time()
        return now - (self.server_timestamp / 1000) > (self.lifetime / 1000)

    @classmethod
    @verify(Schemas.call_invite)
    def from_dict(cls, event_dict):
        content = event_dict.pop("content")
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["lifetime"],
            content["offer"],
        )


@attr.s
class CallAnswerEvent(CallEvent):
    answer = attr.ib()

    @classmethod
    @verify(Schemas.call_answer)
    def from_dict(cls, event_dict):
        content = event_dict.pop("content")
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["answer"],
        )


@attr.s
class CallHangupEvent(CallEvent):
    @classmethod
    @verify(Schemas.call_hangup)
    def from_dict(cls, event_dict):
        content = event_dict.pop("content")
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
        )


@attr.s
class RedactedEvent(Event):
    event_type = attr.ib()
    redacter = attr.ib()
    reason = attr.ib()

    def __str__(self):
        reason = ", reason: {}".format(self.reason) if self.reason else ""
        return "Redacted event of type {}, by {}{}.".format(
            self.event_type, self.redacter, reason
        )

    @classmethod
    @verify(Schemas.redacted_event)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RedactedEvent, BadEventType]
        redacter = parsed_dict["unsigned"]["redacted_because"]["sender"]
        content_dict = parsed_dict["unsigned"]["redacted_because"]["content"]
        reason = content_dict.get("reason", None)

        return cls(
            parsed_dict,
            parsed_dict["type"],
            redacter,
            reason,
        )


@attr.s
class RoomEncryptionEvent(Event):
    pass


@attr.s
class RoomCreateEvent(Event):
    creator = attr.ib()
    federate = attr.ib(default=True)
    room_version = attr.ib(default="1")

    @classmethod
    @verify(Schemas.room_create)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomCreateEvent, BadEventType]
        creator = parsed_dict["content"]["creator"]
        federate = parsed_dict["content"]["m.federate"]
        version = parsed_dict["content"]["room_version"]

        return cls(parsed_dict, creator, federate, version)


@attr.s
class RoomGuestAccessEvent(Event):
    guest_access = attr.ib(default="forbidden")

    @classmethod
    @verify(Schemas.room_guest_access)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomGuestAccessEvent, BadEventType]
        guest_access = parsed_dict["content"]["guest_access"]

        return cls(parsed_dict, guest_access)


@attr.s
class RoomJoinRulesEvent(Event):
    join_rule = attr.ib(default="invite")

    @classmethod
    @verify(Schemas.room_join_rules)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomJoinRulesEvent, BadEventType]
        join_rule = parsed_dict["content"]["join_rule"]

        return cls(parsed_dict, join_rule)


@attr.s
class RoomHistoryVisibilityEvent(Event):
    history_visibility = attr.ib(default="shared")

    @classmethod
    @verify(Schemas.room_history_visibility)
    def from_dict(cls,
                  parsed_dict,  # type: Dict[Any, Any]
                  ):
        # type: (...) -> Union[RoomHistoryVisibilityEvent, BadEventType]
        history_visibility = parsed_dict["content"]["history_visibility"]

        return cls(parsed_dict, history_visibility)


@attr.s
class RoomAliasEvent(Event):
    canonical_alias = attr.ib()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomAliasEvent, BadEventType]
        canonical_alias = parsed_dict["content"]["alias"]

        return cls(parsed_dict, canonical_alias)


@attr.s
class RoomNameEvent(Event):
    name = attr.ib()

    @classmethod
    @verify(Schemas.room_name)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomNameEvent, BadEventType]
        room_name = parsed_dict["content"]["name"]

        return cls(parsed_dict, room_name)


@attr.s
class RoomTopicEvent(Event):
    topic = attr.ib()

    @classmethod
    @verify(Schemas.room_topic)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomTopicEvent, BadEventType]
        canonical_alias = parsed_dict["content"]["topic"]

        return cls(parsed_dict, canonical_alias)


@attr.s
class RoomMessage(Event):
    @classmethod
    @verify(Schemas.room_message)
    def parse_event(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMessage, BadEventType]
        content_dict = parsed_dict["content"]

        if content_dict["msgtype"] == "m.text":
            event = RoomMessageText.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.emote":
            event = RoomMessageEmote.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.notice":
            event = RoomMessageNotice.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.image":
            event = RoomMessageImage.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.audio":
            event = RoomMessageAudio.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.video":
            event = RoomMessageVideo.from_dict(parsed_dict)
        elif content_dict["msgtype"] == "m.file":
            event = RoomMessageFile.from_dict(parsed_dict)
        else:
            event = RoomMessageUnknown.from_dict(parsed_dict)

        if "unsigned" in parsed_dict:
            txn_id = parsed_dict["unsigned"].get("transaction_id", None)
            event.transaction_id = txn_id

        return event


@attr.s
class RoomEncryptedMessage(RoomMessage):
    @classmethod
    @verify(Schemas.room_message)
    def parse_event(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMessage, BadEventType]
        msgtype = parsed_dict["content"]["msgtype"]

        if msgtype == "m.image":
            event = RoomEncryptedImage.from_dict(parsed_dict)
        elif msgtype == "m.audio":
            event = RoomEncryptedAudio.from_dict(parsed_dict)
        elif msgtype == "m.video":
            event = RoomEncryptedVideo.from_dict(parsed_dict)
        elif msgtype == "m.file":
            event = RoomEncryptedFile.from_dict(parsed_dict)
        else:
            event = RoomMessage.parse_event(parsed_dict)

        if "unsigned" in parsed_dict:
            txn_id = parsed_dict["unsigned"].get("transaction_id", None)
            event.transaction_id = txn_id

        return event


@attr.s
class RoomMessageMedia(RoomMessage):
    url = attr.ib()
    body = attr.ib()

    @classmethod
    @verify(Schemas.room_message_media)
    def from_dict(cls, parsed_dict):
        return cls(
            parsed_dict,
            parsed_dict["content"]["url"],
            parsed_dict["content"]["body"],
        )


@attr.s
class RoomEncryptedMedia(RoomMessage):
    url = attr.ib()
    body = attr.ib()
    key = attr.ib()
    hashes = attr.ib()
    iv = attr.ib()

    @classmethod
    @verify(Schemas.room_encrypted_media)
    def from_dict(cls, parsed_dict):
        return cls(
            parsed_dict,
            parsed_dict["content"]["file"]["url"],
            parsed_dict["content"]["body"],
            parsed_dict["content"]["file"]["key"],
            parsed_dict["content"]["file"]["hashes"],
            parsed_dict["content"]["file"]["iv"],
        )


@attr.s
class RoomEncryptedImage(RoomEncryptedMedia):
    pass


@attr.s
class RoomEncryptedAudio(RoomEncryptedMedia):
    pass


@attr.s
class RoomEncryptedVideo(RoomEncryptedMedia):
    pass


@attr.s
class RoomEncryptedFile(RoomEncryptedMedia):
    pass


@attr.s
class RoomMessageImage(RoomMessageMedia):
    pass


@attr.s
class RoomMessageAudio(RoomMessageMedia):
    pass


@attr.s
class RoomMessageVideo(RoomMessageMedia):
    pass


@attr.s
class RoomMessageFile(RoomMessageMedia):
    pass


@attr.s
class RoomMessageUnknown(RoomMessage):
    type = attr.ib()
    content = attr.ib()

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> RoomMessage
        return cls(
            parsed_dict,
            parsed_dict["content"]["msgtype"],
            parsed_dict.pop("content"),
        )


@attr.s
class RoomMessageNotice(RoomMessage):
    body = attr.ib()

    @classmethod
    @verify(Schemas.room_message_notice)
    def from_dict(cls, parsed_dict):
        return cls(
            parsed_dict,
            parsed_dict["content"]["body"],
        )


@attr.s
class RoomMessageText(RoomMessage):
    body = attr.ib()
    formatted_body = attr.ib()
    format = attr.ib()

    def __str__(self):
        # type: () -> str
        return "{}: {}".format(self.sender, self.body)

    @staticmethod
    def _validate(parsed_dict):
        # type: (Dict[Any, Any]) -> Optional[BadEventType]
        return validate_or_badevent(parsed_dict, Schemas.room_message_text)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMessage, BadEventType]
        bad = cls._validate(parsed_dict)

        if bad:
            return bad

        body = parsed_dict["content"]["body"]
        formatted_body = (
            parsed_dict["content"]["formatted_body"]
            if "formatted_body" in parsed_dict["content"]
            else None
        )
        body_format = (
            parsed_dict["content"]["format"]
            if "format" in parsed_dict["content"]
            else None
        )

        return cls(
            parsed_dict,
            body,
            formatted_body,
            body_format,
        )


@attr.s
class RoomMessageEmote(RoomMessageText):
    @staticmethod
    def _validate(parsed_dict):
        # type: (Dict[Any, Any]) -> Optional[BadEventType]
        return validate_or_badevent(parsed_dict, Schemas.room_message_emote)


@attr.s
class DefaultLevels(object):
    ban = attr.ib(default=50, type=int)
    invite = attr.ib(default=50, type=int)
    kick = attr.ib(default=50, type=int)
    redact = attr.ib(default=50, type=int)
    state_default = attr.ib(default=0, type=int)
    events_default = attr.ib(default=0, type=int)
    users_default = attr.ib(default=0, type=int)

    @classmethod
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            content["ban"],
            content["invite"],
            content["kick"],
            content["redact"],
            content["state_default"],
            content["events_default"],
            content["users_default"]
        )


@attr.s
class PowerLevels(object):
    defaults = attr.ib(default=attr.Factory(DefaultLevels))
    users = attr.ib(default=attr.Factory(dict), type=Dict[str, int])
    events = attr.ib(default=attr.Factory(dict), type=Dict[str, int])

    def get_user_level(self, user_id):
        # type: (str) -> int
        if user_id in self.users:
            return self.users[user_id]

        return self.defaults.users_default

    def update(self, new_levels):
        if not isinstance(new_levels, PowerLevels):
            return

        self.defaults = new_levels.defaults
        self.events.update(new_levels.events)
        self.users.update(new_levels.users)


@attr.s
class PowerLevelsEvent(Event):
    power_levels = attr.ib()

    @classmethod
    @verify(Schemas.room_power_levels)
    def from_dict(cls, parsed_dict):
        default_levels = DefaultLevels.from_dict(parsed_dict)

        users = parsed_dict["content"].pop("users")
        events = parsed_dict["content"].pop("events")

        levels = PowerLevels(default_levels, users, events)

        return cls(
            parsed_dict,
            levels,
        )


@attr.s
class RedactionEvent(Event):
    redacts = attr.ib()
    reason = attr.ib(default=None)

    @classmethod
    @verify(Schemas.room_redaction)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RedactionEvent, BadEventType]
        content = parsed_dict.get("content", {})
        reason = content.get("reason", None)

        return cls(
            parsed_dict,
            parsed_dict["redacts"],
            reason,
        )


@attr.s
class RoomMemberEvent(Event):
    state_key = attr.ib()
    content = attr.ib()
    prev_content = attr.ib(default=None)

    @classmethod
    @verify(Schemas.room_membership)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMemberEvent, BadEventType]
        content = parsed_dict.pop("content")
        unsigned = parsed_dict.get("unsigned", {})
        prev_content = unsigned.get("prev_content", None)

        return cls(
            parsed_dict,
            parsed_dict["state_key"],
            content,
            prev_content,
        )
