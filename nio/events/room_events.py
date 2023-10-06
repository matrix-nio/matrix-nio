# Copyright © 2018-2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2021 Famedly GmbH
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

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ..event_builders import RoomKeyRequestMessage
from ..schemas import Schemas
from .misc import BadEvent, BadEventType, UnknownBadEvent, validate_or_badevent, verify


@dataclass
class Event:
    """Matrix Event class.

    This is the base event class, most events inherit from this class.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
        event_id (str): A globally unique event identifier.
        sender (str): The fully-qualified ID of the user who sent this
            event.
        server_timestamp (int): Timestamp in milliseconds on originating
            homeserver when this event was sent.
        decrypted (bool): A flag signaling if the event was decrypted.
        verified (bool): A flag signaling if the event is verified, is True if
            the event was sent from a verified device.
        sender_key (str, optional): The public key of the sender that was used
            to establish the encrypted session. Is only set if decrypted is
            True, otherwise None.
        session_id (str, optional): The unique identifier of the session that
            was used to decrypt the message. Is only set if decrypted is True,
            otherwise None.
        transaction_id (str, optional): The unique identifier that was used
            when the message was sent. Is only set if the message was sent from
            our own device, otherwise None.

    """

    source: Dict[str, Any] = field()

    event_id: str = field(init=False)
    sender: str = field(init=False)
    server_timestamp: int = field(init=False)

    decrypted: bool = field(default=False, init=False)
    verified: bool = field(default=False, init=False)
    sender_key: Optional[str] = field(default=None, init=False)
    session_id: Optional[str] = field(default=None, init=False)
    transaction_id: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        self.event_id = self.source["event_id"]
        self.sender = self.source["sender"]
        self.server_timestamp = self.source["origin_server_ts"]

    def flattened(
        self,
        _prefix: str = "",
        _source: Optional[Dict[str, Any]] = None,
        _flat: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a flattened version of the ``source`` dict with dotted keys.

        Example:
            >>> event.source
            {"content": {"body": "foo"}, "m.test": {"key": "bar"}}
            >>> event.source.flattened()
            {"content.body": "foo", "m.test.key": "bar"}

        """

        source = self.source if _source is None else _source
        flat = {} if _flat is None else _flat

        for key, value in source.items():
            if isinstance(value, dict):
                self.flattened(f"{_prefix}{key}.", value, flat)
            else:
                flat[f"{_prefix}{key}"] = value

        return flat

    @classmethod
    def from_dict(cls, parsed_dict: Dict[Any, Any]) -> Union[Event, BadEventType]:
        """Create an Event from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        return cls(parsed_dict)

    @classmethod
    @verify(Schemas.room_event)
    def parse_event(cls, event_dict: Dict[Any, Any]) -> Union[Event, BadEventType]:
        """Parse a Matrix event and create a higher level event object.

        This function parses the type of the Matrix event and produces a higher
        level event object representing the parsed event.

        The event structure is checked for correctness and the event fields are
        type-checked. If this validation process fails for an event an BadEvent
        will be produced.

        If the type of the event is now known an UnknownEvent will be produced.

        Args:
            event_dict (dict): The dictionary representation of the event.

        """
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
        elif event_dict["type"] == "m.room.avatar":
            return RoomAvatarEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.power_levels":
            return PowerLevelsEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encryption":
            return RoomEncryptionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.redaction":
            return RedactionEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.tombstone":
            return RoomUpgradeEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.space.parent":
            return RoomSpaceParentEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.space.child":
            return RoomSpaceChildEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.encrypted":
            return Event.parse_encrypted_event(event_dict)
        elif event_dict["type"] == "m.sticker":
            return StickerEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.reaction":
            return ReactionEvent.from_dict(event_dict)
        elif event_dict["type"].startswith("m.call"):
            return CallEvent.parse_event(event_dict)

        return UnknownEvent.from_dict(event_dict)

    @classmethod
    @verify(Schemas.room_encrypted)
    def parse_encrypted_event(cls, event_dict):
        """Parse an encrypted event.

        Encrypted events may have different fields depending on the algorithm
        that was used to encrypt them.

        This function checks the algorithm of the event and produces a higher
        level event from the provided dictionary.

        Args:
            event_dict (dict): The dictionary representation of the encrypted
                event.

        Returns None if the algorithm of the event is unknown.
        """
        content = event_dict["content"]

        if content["algorithm"] == "m.megolm.v1.aes-sha2":
            return MegolmEvent.from_dict(event_dict)

        return UnknownEncryptedEvent.from_dict(event_dict)

    @classmethod
    def parse_decrypted_event(
        cls, event_dict: Dict[Any, Any]
    ) -> Union[Event, BadEventType]:
        """Parse a decrypted event and create a higher level event object.

        Args:
            event_dict (dict): The dictionary representation of the event.
        """
        if "unsigned" in event_dict:
            if "redacted_because" in event_dict["unsigned"]:
                return RedactedEvent.from_dict(event_dict)

        # Events shouldn't be encrypted twice, this would lead to a loop in the
        # parser path.
        if event_dict["type"] == "m.room.encrypted":
            try:
                return BadEvent.from_dict(event_dict)
            except KeyError:
                return UnknownBadEvent(event_dict)
        if event_dict["type"] == "m.room.message":
            return RoomMessage.parse_decrypted_event(event_dict)

        return Event.parse_event(event_dict)


@dataclass
class UnknownEvent(Event):
    """An Event which we do not understand.

    This event is created every time nio tries to parse an event of an unknown
    type. Since custom and extensible events are a feature of Matrix this
    allows clients to use custom events but care should be taken that the
    clients will be responsible to validate and type check the event.

    Attributes:
        type (str): The type of the event.

    """

    type: str = field()

    @classmethod
    def from_dict(cls, event_dict):
        return cls(
            event_dict,
            event_dict["type"],
        )


@dataclass
class UnknownEncryptedEvent(Event):
    """An encrypted event which we don't know how to decrypt.

    This event is created every time nio tries to parse an event encrypted
    event that was encrypted using an unknown algorithm.

    Attributes:
        type (str): The type of the event.
        algorithm (str): The algorithm of the event.

    """

    type: str = field()
    algorithm: str = field()

    @classmethod
    def from_dict(cls, event_dict):
        return cls(
            event_dict,
            event_dict["type"],
            event_dict["content"]["algorithm"],
        )


@dataclass
class MegolmEvent(Event):
    """An undecrypted Megolm event.

    MegolmEvents are presented to library users only if the library fails
    to decrypt the event because of a missing session key.

    MegolmEvents can be stored for later use. If a RoomKeyEvent is later on
    received with a session id that matches the session_id of this event
    decryption can be retried.

    Attributes:
        event_id (str): A globally unique event identifier.
        sender (str): The fully-qualified ID of the user who sent this
            event.
        server_timestamp (int): Timestamp in milliseconds on originating
            homeserver when this event was sent.
        sender_key (str): The public key of the sender that was used
            to establish the encrypted session. Is only set if decrypted is
            True, otherwise None.
        device_id (str): The unique identifier of the device that was used to
            encrypt the event.
        session_id (str): The unique identifier of the session that
            was used to encrypt the message.
        ciphertext (str): The undecrypted ciphertext of the event.
        algorithm (str): The encryption algorithm that was used to encrypt the
            message.
        room_id (str): The unique identifier of the room in which the message
            was sent.
        transaction_id (str, optional): The unique identifier that was used
            when the message was sent. Is only set if the message was sent from
            our own device, otherwise None.

    """

    device_id: str = field()
    ciphertext: str = field()
    algorithm: str = field()
    room_id: str = ""

    @classmethod
    @verify(Schemas.room_megolm_encrypted)
    def from_dict(cls, event_dict):
        """Create a MegolmEvent from a dictionary.

        Args:
            event_dict (Dict): Dictionary containing the event.

        Returns a MegolmEvent if the event_dict contains a valid event or a
        BadEvent if it's invalid.
        """
        content = event_dict["content"]

        ciphertext = content["ciphertext"]
        sender_key = content["sender_key"]
        session_id = content["session_id"]
        device_id = content["device_id"]
        algorithm = content["algorithm"]

        room_id = event_dict.get("room_id", None)
        tx_id = (
            event_dict["unsigned"].get("transaction_id", None)
            if "unsigned" in event_dict
            else None
        )

        event = cls(
            event_dict,
            device_id,
            ciphertext,
            algorithm,
            room_id,
        )

        event.sender_key = sender_key
        event.session_id = session_id
        event.transaction_id = tx_id

        return event

    def as_key_request(
        self,
        user_id: str,
        requesting_device_id: str,
        request_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> RoomKeyRequestMessage:
        """Make a to-device message for a room key request.

        MegolmEvents are presented to library users only if the library fails
        to decrypt the event because of a missing session key.

        A missing key can be requested later on by sending a key request, this
        method creates a ToDeviceMessage that can be sent out if such a request
        should be made.

        Args:
            user_id (str): The user id of the user that should receive the key
                request.
            requesting_device_id (str): The device id of the user that is
                requesting the key.
            request_id (str, optional): A unique string identifying the
                request.
                Defaults to the session id of the missing megolm session.
            device_id (str, optional): The device id of the device that should
                receive the request. Defaults to all the users devices.
        """
        assert self.session_id
        request_id = request_id or self.session_id

        content = {
            "action": "request",
            "body": {
                "algorithm": self.algorithm,
                "session_id": self.session_id,
                "room_id": self.room_id,
                "sender_key": self.sender_key,
            },
            "request_id": request_id,
            "requesting_device_id": requesting_device_id,
        }

        return RoomKeyRequestMessage(
            "m.room_key_request",
            user_id,
            device_id or "*",
            content,
            request_id,
            self.session_id,
            self.room_id,
            self.algorithm,
        )


@dataclass
class CallEvent(Event):
    """Base Class for Matrix call signalling events.

    Attributes:
        call_id (str): The unique identifier of the call.
        version (int): The version of the VoIP specification this message
            adheres to.

    """

    call_id: str = field()
    version: int = field()

    @staticmethod
    def parse_event(event_dict):
        """Parse a Matrix event and create a higher level event object.

        This function parses the type of the Matrix event and produces a
        higher level CallEvent object representing the parsed event.

        The event structure is checked for correctness and the event fields are
        type checked. If this validation process fails for an event an BadEvent
        will be produced.

        If the type of the event is now known an UnknownEvent will be produced.

        Args:
            event_dict (dict): The raw matrix event dictionary.

        """
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


@dataclass
class CallCandidatesEvent(CallEvent):
    """Call event holding additional VoIP ICE candidates.

    This event is sent by callers after sending an invite and by the callee
    after answering. Its purpose is to give the other party additional ICE
    candidates to try using to communicate.

    Args:
        candidates (list): A list of dictionaries describing the candidates.
    """

    candidates: List[Dict[str, Any]] = field()

    @classmethod
    @verify(Schemas.call_candidates)
    def from_dict(cls, event_dict):
        content = event_dict.get("content", {})
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["candidates"],
        )


@dataclass
class CallInviteEvent(CallEvent):
    """Event representing an invitation to a VoIP call.

    This event is sent by a caller when they wish to establish a call.

    Attributes:
        lifetime (integer): The time in milliseconds that the invite is valid
            for.
        offer (dict): The session description object. A dictionary containing
            the keys "type" which must be "offer" for this event and "sdp"
            which contains the SDP text of the session description.

    """

    lifetime: int = field()
    offer: Dict[str, Any] = field()

    @property
    def expired(self):
        """Property marking if the invite event expired."""
        now = time.time()
        return now - (self.server_timestamp / 1000) > (self.lifetime / 1000)

    @classmethod
    @verify(Schemas.call_invite)
    def from_dict(cls, event_dict):
        content = event_dict.get("content", {})
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["lifetime"],
            content["offer"],
        )


@dataclass
class CallAnswerEvent(CallEvent):
    """Event representing the answer to a VoIP call.

    This event is sent by the callee when they wish to answer the call.

    Attributes:
        answer (dict): The session description object. A dictionary containing
            the keys "type" which must be "answer" for this event and "sdp"
            which contains the SDP text of the session description.

    """

    answer: Dict[str, Any] = field()

    @classmethod
    @verify(Schemas.call_answer)
    def from_dict(cls, event_dict):
        content = event_dict.get("content", {})
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
            content["answer"],
        )


@dataclass
class CallHangupEvent(CallEvent):
    """An event representing the end of a VoIP call.

    Sent by either party to signal their termination of the call. This can be
    sent either once the call has has been established or before to abort the
    call.

    """

    @classmethod
    @verify(Schemas.call_hangup)
    def from_dict(cls, event_dict):
        content = event_dict.get("content", {})
        return cls(
            event_dict,
            content["call_id"],
            content["version"],
        )


@dataclass
class RedactedEvent(Event):
    """An event that has been redacted.

    Attributes:
        type (str): The type of the event that has been redacted.
        redacter (str): The fully-qualified ID of the user who redacted the
            event.
        reason (str, optional): A string describing why the event was redacted,
            can be None.

    """

    type: str = field()
    redacter: str = field()
    reason: Optional[str] = field()

    def __str__(self):
        reason = f", reason: {self.reason}" if self.reason else ""
        return f"Redacted event of type {self.type}, by {self.redacter}{reason}."

    @property
    def event_type(self):
        """Type of the event."""
        return self.type

    @classmethod
    @verify(Schemas.redacted_event)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RedactedEvent, BadEventType]:
        redacter = parsed_dict["unsigned"]["redacted_because"]["sender"]
        content_dict = parsed_dict["unsigned"]["redacted_because"]["content"]
        reason = content_dict.get("reason", None)

        return cls(
            parsed_dict,
            parsed_dict["type"],
            redacter,
            reason,
        )


@dataclass
class RoomEncryptionEvent(Event):
    """An event signaling that encryption has been enabled in a room."""

    @classmethod
    @verify(Schemas.room_encryption)
    def from_dict(cls, parsed_dict):
        return cls(parsed_dict)


@dataclass
class RoomCreateEvent(Event):
    """The first event in a room, signaling that the room was created.

    Attributes:
        creator (str): The fully-qualified ID of the user who created the room.
        federate (bool): A boolean flag telling us whether users on other
            homeservers are able to join this room.
        room_version (str): The version of the room. Different room versions
            will have different event formats. Clients shouldn't worry about
            this too much unless they want to perform room upgrades.
        room_type (str): The type of the room.
            In spec v1.2 the following room types are specified:
                - `m.space`
            Unspecified room types are permitted through the use of Namespaced Identifiers.

    """

    creator: str = field()
    federate: bool = True
    room_version: str = "1"
    room_type: str = ""

    @classmethod
    @verify(Schemas.room_create)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomCreateEvent, BadEventType]:
        creator = parsed_dict["content"]["creator"]
        federate = parsed_dict["content"]["m.federate"]
        version = parsed_dict["content"]["room_version"]
        if "type" in parsed_dict["content"]:
            room_type = parsed_dict["content"]["type"]

        return cls(parsed_dict, creator, federate, version, room_type)


@dataclass
class RoomGuestAccessEvent(Event):
    """Event signaling whether guest users are allowed to join rooms.

    Attributes:
        guest_access (str): A string describing the guest access policy of the
            room. Can be one of "can_join" or "forbidden".

    """

    guest_access: str = "forbidden"

    @classmethod
    @verify(Schemas.room_guest_access)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomGuestAccessEvent, BadEventType]:
        guest_access = parsed_dict["content"]["guest_access"]

        return cls(parsed_dict, guest_access)


@dataclass
class RoomJoinRulesEvent(Event):
    """An event telling us how users can join the room.

    Attributes:
        join_rule (str): A string telling us how users may join the room, can
            be one of "public" meaning anyone can join the room without any
            restrictions or "invite" meaning users can only join if they have
            been previously invited.

    """

    join_rule: str = "invite"

    @classmethod
    @verify(Schemas.room_join_rules)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomJoinRulesEvent, BadEventType]:
        join_rule = parsed_dict["content"]["join_rule"]

        return cls(parsed_dict, join_rule)


@dataclass
class RoomHistoryVisibilityEvent(Event):
    """An event telling whether users can read the room history.

    Room history visibility can be set up in multiple ways in Matrix:

    * world_readable
        All events value may be shared by any participating
        homeserver with anyone, regardless of whether they have ever joined
        the room.
    * shared
        Previous events are always accessible to newly joined
        members. All events in the room are accessible, even those sent
        when the member was not a part of the room.
    * invited
        Events are accessible to newly joined members from the
        point they were invited onwards. Events stop being accessible when
        the member's state changes to something other than invite or join.
    * joined
        Events are only accessible to members from the point on they
        joined to the room and stop being accessible when they aren't
        joined anymore.

    Attributes:
        history_visibility (str): A string describing who can read the room
            history. One of "invited", "joined", "shared", "world_readable".

    """

    history_visibility: str = "shared"

    @classmethod
    @verify(Schemas.room_history_visibility)
    def from_dict(
        cls,
        parsed_dict: Dict[Any, Any],
    ) -> Union[RoomHistoryVisibilityEvent, BadEventType]:
        history_visibility = parsed_dict["content"]["history_visibility"]

        return cls(parsed_dict, history_visibility)


@dataclass
class RoomAliasEvent(Event):
    """An event informing us about which alias should be preferred.

    Attributes:
        canonical_alias (str): The alias that is considered canonical.

    """

    canonical_alias: str = field()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomAliasEvent, BadEventType]:
        canonical_alias = parsed_dict["content"].get("alias")

        return cls(parsed_dict, canonical_alias)


@dataclass
class RoomNameEvent(Event):
    """Event holding the name of the room.

    The room name is a human-friendly string designed to be displayed to the
    end-user. The room name is not unique, as multiple rooms can have the same
    room name set.

    Attributes:
        name (str): The name of the room.

    """

    name: str = field()

    @classmethod
    @verify(Schemas.room_name)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomNameEvent, BadEventType]:
        room_name = parsed_dict["content"]["name"]

        return cls(parsed_dict, room_name)


@dataclass
class RoomTopicEvent(Event):
    """Event holding the topic of a room.

    A topic is a short message detailing what is currently being discussed in
    the room. It can also be used as a way to display extra information about
    the room, which may not be suitable for the room name.

    Attributes:
        topic (str): The topic of the room.

    """

    topic: str = field()

    @classmethod
    @verify(Schemas.room_topic)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomTopicEvent, BadEventType]:
        canonical_alias = parsed_dict["content"]["topic"]

        return cls(parsed_dict, canonical_alias)


@dataclass
class RoomAvatarEvent(Event):
    """Event holding a picture that is associated with the room.

    Attributes:
        avatar_url (str): The URL to the picture.

    """

    avatar_url: str = field()

    @classmethod
    @verify(Schemas.room_avatar)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomAvatarEvent, BadEventType]:
        room_avatar_url = parsed_dict["content"]["url"]

        return cls(parsed_dict, room_avatar_url)


@dataclass
class RoomSpaceParentEvent(Event):
    """Event holding the parent space of a room.

    Attributes:
        state_key (str): The parent space's room

    """

    state_key: str = field()
    canonical: bool = False

    @classmethod
    @verify(Schemas.room_space_parent)
    def from_dict(cls, parsed_dict):
        content_dict = parsed_dict["content"]
        return cls(
            parsed_dict, parsed_dict["state_key"], content_dict.get("canonical", False)
        )


@dataclass
class RoomSpaceChildEvent(Event):
    """Event holding the child rooms of a space.

    Attributes:
        state_key (str): The child room of a space

    """

    state_key: str = field()
    suggested: bool = False

    @classmethod
    @verify(Schemas.room_space_child)
    def from_dict(cls, parsed_dict):
        content_dict = parsed_dict["content"]
        return cls(
            parsed_dict, parsed_dict["state_key"], content_dict.get("suggested", False)
        )


@dataclass
class RoomMessage(Event):
    """Abstract room message class.

    This class corespondents to a Matrix event of the m.room.message type. It
    is used when messages are sent to the room.

    The class has one child class per msgtype.
    """

    @classmethod
    @verify(Schemas.room_message)
    def parse_event(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomMessage, BadEventType]:
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

    @classmethod
    @verify(Schemas.room_message)
    def parse_decrypted_event(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomMessage, BadEventType]:
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


@dataclass
class RoomMessageMedia(RoomMessage):
    """Base class for room messages containing a URI.

    Attributes:
        url (str): The URL of the file.
        body (str): The description of the message.

    """

    url: str = field()
    body: str = field()

    @classmethod
    @verify(Schemas.room_message_media)
    def from_dict(cls, parsed_dict):
        return cls(
            parsed_dict,
            parsed_dict["content"]["url"],
            parsed_dict["content"]["body"],
        )


@dataclass
class RoomEncryptedMedia(RoomMessage):
    """Base class for encrypted room messages containing an URI.

    Attributes:
        url (str): The URL of the file.
        body (str): The description of the message.
        key (dict): The key that can be used to decrypt the file.
        hashes (dict): A mapping from an algorithm name to a hash of the
            ciphertext encoded as base64.
        iv (str): The initialisation vector that was used to encrypt the file.
        mimetype (str, optional): The mimetype of the message.

        thumbnail_url (str, optional): The URL of the thumbnail file.
        thumbnail_key (dict, optional): The key that can be used to decrypt the
            thumbnail file.
        thumbnail_hashes (dict, optional): A mapping from an algorithm name to
            a hash of the thumbnail ciphertext encoded as base64.
        thumbnail_iv (str, optional): The initialisation vector that was used
            to encrypt the thumbnail file.
    """

    url: str = field()
    body: str = field()
    key: Dict[str, Any] = field()
    hashes: Dict[str, Any] = field()
    iv: str = field()
    mimetype: str = field()

    thumbnail_url: Optional[str] = None
    thumbnail_key: Optional[Dict] = None
    thumbnail_hashes: Optional[Dict] = None
    thumbnail_iv: Optional[str] = None

    @classmethod
    @verify(Schemas.room_encrypted_media)
    def from_dict(cls, parsed_dict):
        info = parsed_dict["content"].get("info", {})
        thumbnail_file = info.get("thumbnail_file", {})

        thumbnail_url = thumbnail_file.get("url")
        thumbnail_key = thumbnail_file.get("key")
        thumbnail_hashes = thumbnail_file.get("hashes")
        thumbnail_iv = thumbnail_file.get("iv")

        mimetype = info.get("mimetype") or parsed_dict["content"]["file"].get(
            "mimetype"
        )

        return cls(
            parsed_dict,
            parsed_dict["content"]["file"]["url"],
            parsed_dict["content"]["body"],
            parsed_dict["content"]["file"]["key"],
            parsed_dict["content"]["file"]["hashes"],
            parsed_dict["content"]["file"]["iv"],
            mimetype,
            thumbnail_url,
            thumbnail_key,
            thumbnail_hashes,
            thumbnail_iv,
        )


@dataclass
class RoomEncryptedImage(RoomEncryptedMedia):
    """A room message containing an image where the file is encrypted."""


@dataclass
class RoomEncryptedAudio(RoomEncryptedMedia):
    """A room message containing an audio clip where the file is encrypted."""


@dataclass
class RoomEncryptedVideo(RoomEncryptedMedia):
    """A room message containing a video clip where the file is encrypted."""


@dataclass
class RoomEncryptedFile(RoomEncryptedMedia):
    """A room message containing a generic encrypted file."""


@dataclass
class RoomMessageImage(RoomMessageMedia):
    """A room message containing an image."""


@dataclass
class RoomMessageAudio(RoomMessageMedia):
    """A room message containing an audio clip."""


@dataclass
class RoomMessageVideo(RoomMessageMedia):
    """A room message containing a video clip."""


@dataclass
class RoomMessageFile(RoomMessageMedia):
    """A room message containing a generic file."""


@dataclass
class RoomMessageUnknown(RoomMessage):
    """A m.room.message which we do not understand.

    This event is created every time nio tries to parse a room message of an
    unknown msgtype. Since custom and extensible events are a feature of Matrix
    this allows clients to use custom messages but care should be taken that
    the clients will be responsible to validate and type check the content of
    the message.

    Attributes:
        msgtype (str): The msgtype of the room message.
        content (dict): The dictionary holding the content of the room message.
            The keys and values of this dictionary will differ depending on the
            msgtype.

    """

    msgtype: str = field()
    content: Dict[str, Any] = field()

    @classmethod
    def from_dict(cls, parsed_dict: Dict[Any, Any]) -> RoomMessage:
        return cls(
            parsed_dict,
            parsed_dict["content"]["msgtype"],
            parsed_dict.get("content", {}),
        )

    @property
    def type(self):
        """Get the msgtype of the room message."""
        return self.msgtype


@dataclass
class RoomMessageFormatted(RoomMessage):
    """Base abstract class for room messages that can have formatted bodies.

    Attributes:
        body (str): The textual body of the message.
        formatted_body (str, optional): The formatted version of the body. Can
            be None if the message doesn't contain a formatted version of the
            body.
        format (str, optional): The format used in the formatted_body. This
            specifies how the formatted_body should be interpreted.

    """

    body: str = field()
    formatted_body: Optional[str] = field()
    format: Optional[str] = field()

    def __str__(self) -> str:
        return f"{self.sender}: {self.body}"

    @staticmethod
    def _validate(parsed_dict):
        raise NotImplementedError

    @classmethod
    def from_dict(cls, parsed_dict: Dict[Any, Any]) -> Union[RoomMessage, BadEventType]:
        bad = cls._validate(parsed_dict)

        if bad:
            return bad

        body = parsed_dict["content"]["body"]
        body_format = parsed_dict["content"].get("format")

        # Only try to find the formatted body if the format is specified. It is
        # required by the spec to have both or none specified.
        if body_format:
            formatted_body = parsed_dict["content"].get("formatted_body")
        else:
            formatted_body = None

        return cls(
            parsed_dict,
            body,
            formatted_body,
            body_format,
        )


@dataclass
class RoomMessageText(RoomMessageFormatted):
    """A room message corresponding to the m.text msgtype.

    This message is the most basic message and is used to represent text.

    Attributes:
        body (str): The textual body of the message.
        formatted_body (str, optional): The formatted version of the body. Can
            be None if the message doesn't contain a formatted version of the
            body.
        format (str, optional): The format used in the formatted_body. This
            specifies how the formatted_body should be interpreted.

    """

    @staticmethod
    def _validate(parsed_dict: Dict[Any, Any]) -> Optional[BadEventType]:
        return validate_or_badevent(parsed_dict, Schemas.room_message_text)


@dataclass
class RoomMessageEmote(RoomMessageFormatted):
    """A room message corresponding to the m.emote msgtype.

    This message is similar to m.text except that the sender is 'performing'
    the action contained in the body key, similar to /me in IRC.

    Attributes:
        body (str): The textual body of the message.
        formatted_body (str, optional): The formatted version of the body. Can
            be None if the message doesn't contain a formatted version of the
            body.
        format (str, optional): The format used in the formatted_body. This
            specifies how the formatted_body should be interpreted.

    """

    @staticmethod
    def _validate(parsed_dict: Dict[Any, Any]) -> Optional[BadEventType]:
        return validate_or_badevent(parsed_dict, Schemas.room_message_emote)


@dataclass
class RoomMessageNotice(RoomMessageFormatted):
    """A room message corresponding to the m.notice msgtype.

    Room notices are primarily intended for responses from automated
    clients.

    Attributes:
        body (str): The textual body of the notice.
        formatted_body (str, optional): The formatted version of the notice
            body. Can be None if the message doesn't contain a formatted
            version of the body.
        format (str, optional): The format used in the formatted_body. This
            specifies how the formatted_body should be interpreted.
    """

    @staticmethod
    def _validate(parsed_dict: Dict[Any, Any]) -> Optional[BadEventType]:
        return validate_or_badevent(parsed_dict, Schemas.room_message_notice)


@dataclass
class DefaultLevels:
    """Class holding information about default power levels of a room.

    Attributes:
        ban (int): The level required to ban a user.
        invite (int): The level required to invite a user.
        kick (int): The level required to kick a user.
        redact (int): The level required to redact events.
        state_default (int): The level required to send state events. This can
            be overridden by the events power level mapping.
        events_default (int): The level required to send message events. This
            can be overridden by the events power level mapping.
        users_default (int): The default power level for every user in the
            room. This can be overridden by the users power level mapping.
        notifications (Dict[str, int]): The level required to send different
            kinds of notifications. Used for ``sender_notification_permission``
            conditions in push rules.
    """

    ban: int = 50
    invite: int = 50
    kick: int = 50
    redact: int = 50
    state_default: int = 0
    events_default: int = 0
    users_default: int = 0
    notifications: Dict[str, int] = field(default_factory=lambda: {"room": 50})

    @classmethod
    def from_dict(cls, parsed_dict):
        """Create a DefaultLevels object from a dictionary.

        This creates the DefaultLevels object from a dictionary containing a
        m.room.power_levels event. The event structure isn't checked in this
        method.

        This shouldn't be used directly, the `PowerLevelsEvent` method will
        call this method to construct the DefaultLevels object.
        """
        content = parsed_dict["content"]
        return cls(
            content["ban"],
            content["invite"],
            content["kick"],
            content["redact"],
            content["state_default"],
            content["events_default"],
            content["users_default"],
            content["notifications"],
        )


@dataclass
class PowerLevels:
    """Class holding information of room power levels.

    Attributes:
        defaults (DefaultLevels): The default power levels of the room.
        users (dict): The power levels for specific users. This is a mapping
            from user_id to power level for that user.
        events (dict): The level required to send specific event types. This is
            a mapping from event type to power level required.

    """

    defaults: DefaultLevels = field(default_factory=DefaultLevels)
    users: Dict[str, int] = field(default_factory=dict)
    events: Dict[str, int] = field(default_factory=dict)

    def get_state_event_required_level(self, event_type: str) -> int:
        """Get required power level to send a certain type of state event.

        Returns an integer representing the required power level.

        Args:
            event_type (str): The type of matrix state event we want the
                required level for, e.g. `m.room.name` or `m.room.topic`.
        """
        return self.events.get(event_type, self.defaults.state_default)

    def get_message_event_required_level(self, event_type: str) -> int:
        """Get required power level to send a certain type of message event.

        Returns an integer representing the required power level.

        Args:
            event_type (str): The type of matrix message event we want the
                required level for, e.g. `m.room.message`.
        """
        return self.events.get(event_type, self.defaults.events_default)

    def get_notification_required_level(self, notification_type: str) -> int:
        """Get required power level to send a certain type of notification.

        Returns an integer representing the required power level.

        Args:
            notification_type (str): The type of notification to get the
                required level for, e.g. ``"room"``.
        """
        return self.defaults.notifications.get(notification_type, 50)

    def get_user_level(self, user_id: str) -> int:
        """Get the power level of a user.

        Returns an integer representing the user's power level.

        Args:
            user_id (str): The fully-qualified ID of the user for whom we would
                like to get the power level.
        """
        return self.users.get(user_id, self.defaults.users_default)

    def can_user_send_state(self, user_id: str, event_type: str) -> bool:
        """Return whether a user has enough power to send certain state events.

        Args:
            user_id (str): The user to check the power of.
            event_type (str): The type of matrix state event to check the
                required power of, e.g. `m.room.encryption`.
        """
        required_level = self.get_state_event_required_level(event_type)
        return self.get_user_level(user_id) >= required_level

    def can_user_send_message(
        self, user_id: str, event_type: str = "m.room.message"
    ) -> bool:
        """
        Return whether a user has enough power to send certain message events.

        Args:
            user_id (str): The user to check the power of.
            event_type (str): The type of matrix message event to check the
                required power of, `m.room.message` by default.
        """
        required_level = self.get_message_event_required_level(event_type)
        return self.get_user_level(user_id) >= required_level

    def can_user_invite(self, user_id: str) -> bool:
        """Return whether a user has enough power to invite others."""
        return self.get_user_level(user_id) >= self.defaults.invite

    def can_user_kick(
        self,
        user_id: str,
        target_user_id: Optional[str] = None,
    ) -> bool:
        """Return whether a user has enough power to kick another.

        If ``target_user_id`` is ``None``, returns whether ``user_id`` has
        enough power to kick anyone with a lower power level than that user.
        """
        level = self.get_user_level(user_id)
        can_kick_lower = level >= self.defaults.kick

        if target_user_id is None:
            return can_kick_lower

        return can_kick_lower and level > self.get_user_level(target_user_id)

    def can_user_ban(
        self,
        user_id: str,
        target_user_id: Optional[str] = None,
    ) -> bool:
        """Return whether a user has enough power to ban another.

        If ``target_user_id`` is ``None``, returns whether ``user_id`` has
        enough power to ban anyone with a lower power level than that user.
        """
        level = self.get_user_level(user_id)
        can_ban_lower = level >= self.defaults.ban

        if target_user_id is None:
            return can_ban_lower

        return can_ban_lower and level > self.get_user_level(target_user_id)

    def can_user_redact(self, user_id: str):
        """Return whether a user has enough power to redact other user's events."""
        return self.get_user_level(user_id) >= self.defaults.redact

    def can_user_notify(self, user_id: str, notification_type: str):
        """Return whether user has enough power to send a type of notification."""
        required = self.get_notification_required_level(notification_type)
        return self.get_user_level(user_id) >= required

    def update(self, new_levels):
        """Update the power levels object with new levels.

        Args:
            new_levels (PowerLevels): A new PowerLevels object that we received
                from a newer PowerLevelsEvent.
        """
        if not isinstance(new_levels, PowerLevels):
            return

        self.defaults = new_levels.defaults
        self.events.update(new_levels.events)
        self.users.update(new_levels.users)


@dataclass
class PowerLevelsEvent(Event):
    """Class representing a m.room.power_levels event.

    This event specifies the minimum level a user must have in order to perform
    a certain action. It also specifies the levels of each user in the room.

    Attributes:
        power_levels (PowerLevels): The PowerLevels object holding information
            of the power levels of the room.

    """

    power_levels: PowerLevels = field()

    @classmethod
    @verify(Schemas.room_power_levels)
    def from_dict(cls, parsed_dict):
        default_levels = DefaultLevels.from_dict(parsed_dict)

        users = parsed_dict["content"].get("users", {})
        events = parsed_dict["content"].get("events", {})

        levels = PowerLevels(default_levels, users, events)

        return cls(
            parsed_dict,
            levels,
        )


@dataclass
class RedactionEvent(Event):
    """An event signaling that another event has been redacted.

    Events can be redacted by either room or server administrators. Redacting
    an event means that all keys not required by the protocol are stripped off.

    Attributes:
        redacts (str): The event id of the event that has been redacted.
        reason (str, optional): A string describing why the event was redacted,
            can be None.

    """

    redacts: str = field()
    reason: Optional[str] = None

    @classmethod
    @verify(Schemas.room_redaction)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RedactionEvent, BadEventType]:
        content = parsed_dict.get("content", {})
        reason = content.get("reason", None)

        return cls(
            parsed_dict,
            parsed_dict["redacts"],
            reason,
        )


@dataclass
class RoomMemberEvent(Event):
    """Class representing to an m.room.member event.

    Attributes:
        state_key (str): The user_id this membership event relates to. In all
            cases except for when membership is join, the user ID in the sender
            attribute does not need to match the user ID in the state_key.
        membership (str): The membership state of the user. One of "invite",
            "join", "leave", "ban", "knock".
        prev_membership (str, optional): The previous membership state that
            this one is overwriting. Can be None in which case the membership
            state is assumed to have been "leave".
        content (dict): The content of the of the membership event.
        prev_content(dict, optional): The content of a previous membership
            event that this one is overwriting.

    """

    state_key: str = field()
    membership: str = field()
    prev_membership: Optional[str] = field()
    content: Dict[str, Any] = field()
    prev_content: Optional[Dict[str, Any]] = None

    @classmethod
    @verify(Schemas.room_membership)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[RoomMemberEvent, BadEventType]:
        content = parsed_dict.get("content", {})
        unsigned = parsed_dict.get("unsigned", {})
        prev_content = unsigned.get("prev_content", None)

        membership = content["membership"]
        prev_membership = prev_content.get("membership") if prev_content else None

        return cls(
            parsed_dict,
            parsed_dict["state_key"],
            membership,
            prev_membership,
            content,
            prev_content,
        )


@dataclass
class StickerEvent(Event):
    """An event indicating the use of a sticker

    Sticker messages are specialised image messages that are displayed
    without controls. Sticker messages are intended to provide simple
    "reaction" events in the message timeline.

    Attributes:
        body (str): A textual representation or associated description of
        the sticker image. This could be the alt text of the original image,
        or a message to accompany and further describe the sticker.
        url (str): The URL to the sticker image.
        content (dict): The content of the of the redaction event.

    """

    body: str = field()
    url: str = field()
    content: Dict[str, Any] = field()

    @classmethod
    @verify(Schemas.sticker)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[StickerEvent, BadEventType]:
        content = parsed_dict.get("content", {})

        body = content["body"]
        url = content["url"]

        return cls(
            parsed_dict,
            body,
            url,
            content,
        )


@dataclass
class ReactionEvent(Event):
    """An event representing an m.reaction event.

    Users sometimes wish to respond to a message using emojis. When such
    responses are grouped visually below the message being reacted to, this
    provides a (visually) lightweight way for users to react to messages.

    Attributes:
        reacts_to (str): The event_id of the message the reaction relates to.
        key (str): The actual reaction/emoji.

    """

    reacts_to: str = field()
    key: str = field()

    @classmethod
    @verify(Schemas.reaction)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]["m.relates_to"]

        return cls(
            parsed_dict,
            content["event_id"],
            content["key"],
        )


@dataclass
class RoomUpgradeEvent(Event):
    """Class representing to an m.room.tombstone event.

    A state event signifying that a room has been upgraded to a
    different room version, and that clients should go there.

    Attributes:
        body (str): A server-defined message.
        replacement_room (str): The new room the client should be visiting.
    """

    body: str = field()
    replacement_room: str = field()

    @classmethod
    @verify(Schemas.room_tombstone)
    def from_dict(cls, parsed_dict):
        content = parsed_dict.get("content", {})
        body = content.get("body", "")
        replacement_room = content.get("replacement_room", "")

        return cls(
            parsed_dict,
            body,
            replacement_room,
        )
