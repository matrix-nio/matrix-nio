# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
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

import attr
import time

from typing import Any, Dict, Optional, Union

from functools import wraps
from builtins import super
from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .api import Api
from .log import logger_group
from .schemas import Schemas, validate_json

logger = Logger("nio.events")
logger_group.add_logger(logger)


def validate_or_badevent(
    parsed_dict,  # type: Dict[Any, Any]
    schema        # type: Dict[Any, Any]
):
    # type: (...) -> Optional[Union[BadEvent, UnknownBadEvent]]
    try:
        validate_json(parsed_dict, schema)
    except (ValidationError, SchemaError) as e:
        logger.error("Error validating event: {}".format(str(e)))
        try:
            return BadEvent.from_dict(parsed_dict)
        except KeyError:
            return UnknownBadEvent(parsed_dict)

    return None


def verify(schema):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            event_dict = args[1]

            bad = validate_or_badevent(event_dict, schema)
            if bad:
                return bad

            return f(*args, **kwargs)
        return wrapper
    return decorator


@attr.s
class UnknownBadEvent(object):
    event_dict = attr.ib()
    transaction_id = attr.ib(default=None, init=False)


@attr.s
class Event(object):
    event_id = attr.ib()
    sender = attr.ib()
    server_timestamp = attr.ib()
    decrypted = attr.ib(default=False, init=False)
    verified = attr.ib(default=False, init=False)
    sender_key = attr.ib(default=None, init=False)  # type: Optional[str]
    session_id = attr.ib(default=None, init=False)  # type: Optional[str]
    transaction_id = attr.ib(default=None, init=False)  # type: Optional[str]

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[Event, UnknownBadEvent]
        return cls(
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
        )

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
    event_dict = attr.ib()

    @classmethod
    def from_dict(cls, event_dict):
        return cls(
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
            event_dict["type"],
            event_dict
        )


@attr.s
class EncryptedEvent(Event):
    @classmethod
    def parse_event(
        cls,
        event_dict,  # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[Event, UnknownBadEvent]
        if "unsigned" in event_dict:
            if "redacted_because" in event_dict["unsigned"]:
                return RedactedEvent.from_dict(event_dict)

        if event_dict["type"] == "m.room.message":
            return RoomEncryptedMessage.parse_event(event_dict)
        return super().parse_event(event_dict)


@attr.s
class AccountDataEvent(object):
    """Abstract class for account data events."""

    @classmethod
    @verify(Schemas.account_data)
    def parse_event(
        cls,
        event_dict,  # type: Dict[Any, Any]
    ):

        if event_dict["type"] == "m.fully_read":
            return FullyReadEvent.from_dict(event_dict)

        return UnknownAccountDataEvent.from_dict(event_dict)


@attr.s
class FullyReadEvent(AccountDataEvent):
    """Read marker location event.

    The current location of the user's read marker in a room.
    This event appears in the user's room account data for the room the marker
    is applicable for.

    Attributes:
        event_id (str): The event id the user's read marker is located
            at in the room.

    """

    event_id = attr.ib()

    @classmethod
    @verify(Schemas.fully_read)
    def from_dict(cls, event_dict):
        """Construct a FullyReadEvent from a dictionary."""
        content = event_dict.pop("content")
        return cls(
            content["event_id"],
        )


@attr.s
class UnknownAccountDataEvent(AccountDataEvent):
    """Account data event of an unknown type.

    Attributes:
        type (str): The type of the event.
        content (Dict): The content of the event.

    """

    type = attr.ib()
    content = attr.ib()

    @classmethod
    def from_dict(cls, event_dict):
        """Construct an UnknownAccountDataEvent from a dictionary."""
        content = event_dict.pop("content")
        return cls(
            event_dict["type"],
            content
        )


@attr.s
class CallEvent(Event):
    call_id = attr.ib()
    version = attr.ib()

    @staticmethod
    def parse_event(event_dict):
        event = None

        if event_dict["type"] == "m.call.candidates":
            event = CallCandidatesEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.invite":
            event = CallInviteEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.answer":
            event = CallAnswerEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.call.hangup":
            event = CallHangupEvent.from_dict(event_dict)

        return event


@attr.s
class CallCandidatesEvent(CallEvent):
    candidates = attr.ib()

    @classmethod
    @verify(Schemas.call_candidates)
    def from_dict(cls, event_dict):
        content = event_dict.pop("content")
        return cls(
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
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
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
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
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
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
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
            content["call_id"],
            content["version"],
        )


@attr.s
class ToDeviceEvent(object):
    sender = attr.ib()

    @classmethod
    @verify(Schemas.to_device)
    def parse_event(
        cls,
        event_dict  # type: Dict[Any, Any]
    ):
        # type: (...) -> Optional[Union[ToDeviceEvent, BadEventType]]
        # A redacted event will have an empty content.
        if not event_dict["content"]:
            return None

        if event_dict["type"] == "m.room.encrypted":
            return RoomEncryptedEvent.parse_event(event_dict)

        return None


@attr.s
class RoomEncryptedEvent(object):
    @classmethod
    @verify(Schemas.room_encrypted)
    def parse_event(cls, event_dict):
        content = event_dict["content"]

        if content["algorithm"] == "m.olm.v1.curve25519-aes-sha2":
            return OlmEvent.from_dict(event_dict)
        elif content["algorithm"] == "m.megolm.v1.aes-sha2":
            return MegolmEvent.from_dict(event_dict)

        return None


@attr.s
class OlmEvent(ToDeviceEvent, RoomEncryptedEvent):
    sender_key = attr.ib()
    ciphertext = attr.ib()
    transaction_id = attr.ib(default=None)

    @classmethod
    @verify(Schemas.room_olm_encrypted)
    def from_dict(cls, event_dict):
        content = event_dict["content"]

        ciphertext = content["ciphertext"]
        sender_key = content["sender_key"]

        tx_id = (event_dict["unsigned"].get("transaction_id", None)
                 if "unsigned" in event_dict else None)

        return cls(event_dict["sender"], sender_key, ciphertext, tx_id)


@attr.s
class RoomKeyEvent(object):
    sender = attr.ib(type=str)
    sender_key = attr.ib(type=str)
    room_id = attr.ib(type=str)
    session_id = attr.ib(type=str)
    algorithm = attr.ib(type=str)

    @classmethod
    @verify(Schemas.room_key_event)
    def from_dict(cls, event_dict, sender, sender_key):
        content = event_dict["content"]

        return cls(
            sender,
            sender_key,
            content["room_id"],
            content["session_id"],
            content["algorithm"]
        )


@attr.s
class ForwardedRoomKeyEvent(RoomKeyEvent):
    """Event containing a room key that got forwarded to us.

    Attributes:
        sender (str): The sender of the event.
        sender_key (str): The key of the sender that sent the event.
        room_id (str): The room ID of the room to which the session key
            belongs to.
        session_id (str): The session id of the session key.
        algorithm: (str): The algorithm of the session key.

    """

    @classmethod
    @verify(Schemas.forwarded_room_key_event)
    def from_dict(cls, event_dict, sender, sender_key):
        """Create a ForwardedRoomKeyEvent from a event dictionary.

        Args:
            event_dict (Dict): The dictionary containing the event.
            sender (str): The sender of the event.
            sender_key (str): The key of the sender that sent the event.
        """
        content = event_dict["content"]

        return cls(
            sender,
            sender_key,
            content["room_id"],
            content["session_id"],
            content["algorithm"]
        )


@attr.s
class MegolmEvent(RoomEncryptedEvent):
    event_id = attr.ib()
    sender = attr.ib()
    server_timestamp = attr.ib()
    sender_key = attr.ib()
    device_id = attr.ib()
    session_id = attr.ib()
    ciphertext = attr.ib()
    algorithm = attr.ib()
    room_id = attr.ib(default="")
    transaction_id = attr.ib(default=None)

    decrypted = attr.ib(default=False, init=False)
    verified = attr.ib(default=False, init=False)

    @classmethod
    @verify(Schemas.room_megolm_encrypted)
    def from_dict(cls, event_dict):
        content = event_dict["content"]

        ciphertext = content["ciphertext"]
        sender_key = content["sender_key"]
        session_id = content["session_id"]
        device_id = content["device_id"]
        algorithm = content["algorithm"]

        room_id = event_dict.get("room_id", None)
        tx_id = (event_dict["unsigned"].get("transaction_id", None)
                 if "unsigned" in event_dict else None)

        return cls(
            event_dict["event_id"],
            event_dict["sender"],
            event_dict["origin_server_ts"],
            sender_key,
            device_id,
            session_id,
            ciphertext,
            algorithm,
            room_id,
            tx_id
        )


@attr.s
class InviteEvent(object):
    sender = attr.ib()

    @classmethod
    def parse_event(cls, event_dict):
        # type: (Dict[Any, Any]) -> Optional[Union[InviteEvent, BadEventType]]
        if "unsigned" in event_dict:
            if "redacted_because" in event_dict["unsigned"]:
                return None

        if event_dict["type"] == "m.room.member":
            return InviteMemberEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.canonical_alias":
            return InviteAliasEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.name":
            return InviteNameEvent.from_dict(event_dict)

        return None


@attr.s
class InviteMemberEvent(InviteEvent):
    state_key = attr.ib()
    content = attr.ib()
    prev_content = attr.ib(default=None)

    @classmethod
    @verify(Schemas.room_membership)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[InviteMemberEvent, BadEventType]
        content = parsed_dict.pop("content")
        unsigned = parsed_dict.get("unsigned", {})
        prev_content = unsigned.get("prev_content", None)

        return cls(
            parsed_dict["sender"],
            parsed_dict["state_key"],
            content,
            prev_content,
        )


@attr.s
class InviteAliasEvent(InviteEvent):
    canonical_alias = attr.ib()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[InviteAliasEvent, BadEventType]
        sender = parsed_dict["sender"]
        canonical_alias = parsed_dict["content"]["alias"]

        return cls(sender, canonical_alias)


@attr.s
class InviteNameEvent(InviteEvent):
    name = attr.ib()

    @classmethod
    @verify(Schemas.room_name)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[InviteNameEvent, BadEventType]
        sender = parsed_dict["sender"]
        canonical_alias = parsed_dict["content"]["name"]

        return cls(sender, canonical_alias)


@attr.s
class BadEvent(Event):
    type = attr.ib()
    source = attr.ib()

    def __str__(self):
        return "Bad event of type {}, from {}.".format(self.type, self.sender)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> BadEvent
        timestamp = parsed_dict["origin_server_ts"]

        timestamp = timestamp if timestamp > 0 else 0
        return cls(
            parsed_dict["event_id"],
            parsed_dict["sender"],
            timestamp,
            parsed_dict["type"],
            Api.to_json(parsed_dict),
        )


BadEventType = Union[BadEvent, UnknownBadEvent]


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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
            parsed_dict["type"],
            redacter,
            reason,
        )


@attr.s
class RoomEncryptionEvent(Event):
    pass


@attr.s
class RoomAliasEvent(Event):
    canonical_alias = attr.ib()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomAliasEvent, BadEventType]
        event_id = parsed_dict["event_id"]
        sender = parsed_dict["sender"]
        timestamp = parsed_dict["origin_server_ts"]

        canonical_alias = parsed_dict["content"]["alias"]

        return cls(event_id, sender, timestamp, canonical_alias)


@attr.s
class RoomNameEvent(Event):
    name = attr.ib()

    @classmethod
    @verify(Schemas.room_name)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomNameEvent, BadEventType]
        event_id = parsed_dict["event_id"]
        sender = parsed_dict["sender"]
        timestamp = parsed_dict["origin_server_ts"]

        room_name = parsed_dict["content"]["name"]

        return cls(event_id, sender, timestamp, room_name)


@attr.s
class RoomTopicEvent(Event):
    topic = attr.ib()

    @classmethod
    @verify(Schemas.room_topic)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomTopicEvent, BadEventType]
        event_id = parsed_dict["event_id"]
        sender = parsed_dict["sender"]
        timestamp = parsed_dict["origin_server_ts"]

        canonical_alias = parsed_dict["content"]["topic"]

        return cls(event_id, sender, timestamp, canonical_alias)


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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
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
            parsed_dict["event_id"],
            parsed_dict["sender"],
            parsed_dict["origin_server_ts"],
            parsed_dict["state_key"],
            content,
            prev_content,
        )
