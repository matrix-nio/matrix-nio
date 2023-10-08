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

"""nio to-device events.

To-device events are events that are sent directly between two devices instead
of normally sending events in a room.

To-device events can be sent to a specific device of a user or to all devices
of a user.

"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from ..schemas import Schemas
from .common import (
    KeyVerificationAcceptMixin,
    KeyVerificationCancelMixin,
    KeyVerificationEventMixin,
    KeyVerificationKeyMixin,
    KeyVerificationMacMixin,
    KeyVerificationStartMixin,
)
from .misc import BadEventType, logger, verify


@dataclass
class ToDeviceEvent:
    """Base Event class for events that are sent using the to-device endpoint.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
        sender (str): The fully-qualified ID of the user who sent this
            event.

    """

    source: Dict[str, Any] = field()
    sender: str = field()

    @classmethod
    @verify(Schemas.to_device)
    def parse_event(
        cls, event_dict: Dict
    ) -> Optional[Union[ToDeviceEvent, BadEventType]]:
        """Parse a to-device event and create a higher level event object.

        This function parses the type of the to-device event and produces a
        higher level event object representing the parsed event.

        The event structure is checked for correctness and the event fields are
        type-checked. If this validation process fails for an event None will
        be returned.

        Args:
            event_dict (dict): The dictionary representation of the event.

        """
        # A redacted event will have an empty content.
        if not event_dict["content"]:
            return None

        if event_dict["type"] == "m.room.encrypted":
            return ToDeviceEvent.parse_encrypted_event(event_dict)
        elif event_dict["type"] == "m.key.verification.start":
            return KeyVerificationStart.from_dict(event_dict)
        elif event_dict["type"] == "m.key.verification.accept":
            return KeyVerificationAccept.from_dict(event_dict)
        elif event_dict["type"] == "m.key.verification.key":
            return KeyVerificationKey.from_dict(event_dict)
        elif event_dict["type"] == "m.key.verification.mac":
            return KeyVerificationMac.from_dict(event_dict)
        elif event_dict["type"] == "m.key.verification.cancel":
            return KeyVerificationCancel.from_dict(event_dict)
        elif event_dict["type"] == "m.room_key_request":
            return BaseRoomKeyRequest.parse_event(event_dict)

        return None

    @classmethod
    @verify(Schemas.room_encrypted)
    def parse_encrypted_event(cls, event_dict):
        """Parse an encrypted to-device event.

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

        if content["algorithm"] == "m.olm.v1.curve25519-aes-sha2":
            return OlmEvent.from_dict(event_dict)

        logger.warning(
            f"Received an encrypted event with an unknown algorithm {content['algorithm']}."
        )

        return None

    @classmethod
    def from_dict(cls, parsed_dict):
        """Create an Event from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        raise NotImplementedError


@dataclass
class BaseRoomKeyRequest(ToDeviceEvent):
    """Base class for room key requests.
    requesting_device_id (str): The id of the device that is requesting the
        key.
    request_id (str): A unique identifier for the request.
    """

    requesting_device_id: str = field()
    request_id: str = field()

    @classmethod
    @verify(Schemas.room_key_request_cancel)
    def parse_event(cls, event_dict):
        if event_dict["content"]["action"] == "request":
            return RoomKeyRequest.from_dict(event_dict)

        return RoomKeyRequestCancellation.from_dict(event_dict)


@dataclass
class RoomKeyRequest(BaseRoomKeyRequest):
    """Event signaling that a room key was requested from us.

    Attributes:
        algorithm (str, optional): The encryption algorithm the requested key
            in this event is to be used with. Will be set only if the action is
            'request'.
        room_id (str, optional): The id of the room that the key is used in.
            Will be set only if the action is 'request'.
        sender_key (str, optional): The key of the device that initiated the
            session. Will be set only if the action is 'request'.
        session_id (str, optional): The id of the session the key is for. Will
        be set only if the action is 'request'.
    """

    algorithm: str = field()
    room_id: str = field()
    sender_key: str = field()
    session_id: str = field()

    @classmethod
    @verify(Schemas.room_key_request)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        body = content["body"]

        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["requesting_device_id"],
            content["request_id"],
            body["algorithm"],
            body["room_id"],
            body["sender_key"],
            body["session_id"],
        )


@dataclass
class RoomKeyRequestCancellation(BaseRoomKeyRequest):
    """Event signaling that a previous room key request was canceled."""

    @classmethod
    @verify(Schemas.room_key_request_cancel)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]

        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["requesting_device_id"],
            content["request_id"],
        )


@dataclass
class KeyVerificationEvent(KeyVerificationEventMixin, ToDeviceEvent):
    """Base class for key verification events.

    Attributes:
        transaction_id (str): An opaque identifier for the verification
            process. Must be unique with respect to the devices involved.

    """


@dataclass
class KeyVerificationStart(KeyVerificationStartMixin, KeyVerificationEvent):
    """Event signaling the start of a SAS key verification process.

    Attributes:
        from_device (str): The device ID which is initiating the process.
        method (str): The verification method to use.
        key_agreement_protocols (list): A list of strings specifying the
            key agreement protocols the sending device understands.
        hashes (list): A list of strings specifying the hash methods the
            sending device understands.
        message_authentication_codes (list): A list of strings specifying the
            message authentication codes that the sending device understands.
        short_authentication_string (list): A list of strings specifying the
            SAS methods the sending device (and the sending device's user)
            understands.

    """

    @classmethod
    @verify(Schemas.key_verification_start)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["transaction_id"],
            content["from_device"],
            content["method"],
            content["key_agreement_protocols"],
            content["hashes"],
            content["message_authentication_codes"],
            content["short_authentication_string"],
        )


@dataclass
class KeyVerificationAccept(KeyVerificationAcceptMixin, KeyVerificationEvent):
    """Event signaling that the SAS verification start has been accepted.

    Attributes:
        commitment (str): The commitment value of the verification process.
        key_agreement_protocol (str): The key agreement protocol the device is
            choosing to use
        hash (str): A list of strings specifying the hash methods the
            sending device understands.
        message_authentication_code (str): The message authentication code the
            device is choosing to use.
        short_authentication_string (list): A list of strings specifying the
            SAS methods that can be used in the verification process.

    """

    @classmethod
    @verify(Schemas.key_verification_accept)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["transaction_id"],
            content["commitment"],
            content["key_agreement_protocol"],
            content["hash"],
            content["message_authentication_code"],
            content["short_authentication_string"],
        )


@dataclass
class KeyVerificationKey(KeyVerificationKeyMixin, KeyVerificationEvent):
    """Event carrying a key verification key.

    After this event is received the short authentication string can be shown
    to the user.

    Attributes:
        key (str): The device's ephemeral public key, encoded as
            unpadded base64.

    """

    @classmethod
    @verify(Schemas.key_verification_key)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["transaction_id"],
            content["key"],
        )


@dataclass
class KeyVerificationMac(KeyVerificationMacMixin, KeyVerificationEvent):
    """Event holding a message authentication code of the verification process.

    After this event is received the device that we are verifying will be
    marked as verified given that we have accepted the short authentication
    string as well.

    Attributes:
        mac (dict): A map of the key ID to the MAC of the key, using the
            algorithm in the verification process. The MAC is encoded as
            unpadded base64.
        keys (str): The MAC of the comma-separated, sorted, list of key IDs
            given in the mac property, encoded as unpadded base64.

    """

    @classmethod
    @verify(Schemas.key_verification_mac)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["transaction_id"],
            content["mac"],
            content["keys"],
        )


@dataclass
class KeyVerificationCancel(KeyVerificationCancelMixin, KeyVerificationEvent):
    """Event signaling that a key verification process has been canceled.

    Attributes:
        code (str): The error code for why the process/request was canceled by
            the user.
        reason (str): A human readable description of the cancellation code.

    """

    @classmethod
    @verify(Schemas.key_verification_cancel)
    def from_dict(cls, parsed_dict):
        content = parsed_dict["content"]
        return cls(
            parsed_dict,
            parsed_dict["sender"],
            content["transaction_id"],
            content["code"],
            content["reason"],
        )


@dataclass
class EncryptedToDeviceEvent(ToDeviceEvent):
    pass


@dataclass
class OlmEvent(EncryptedToDeviceEvent):
    """An Olm encrypted event.

    Olm events are used to exchange end to end encrypted messages between two
    devices. They will mostly contain encryption keys to establish a Megolm
    session for a room.

    nio users will never see such an event under normal circumstances since
    decrypting this event will produce an event of another type.

    Attributes:
        sender (str): The fully-qualified ID of the user who sent this
            event.
        sender_key (str, optional): The public key of the sender that was used
            to establish the encrypted session.
        ciphertext (Dict[str, Any]): The undecrypted ciphertext of the event.
        transaction_id (str, optional): The unique identifier that was used
            when the message was sent. Is only set if the message was sent from
            our own device, otherwise None.

    """

    sender_key: str = field()
    ciphertext: Dict[str, Any] = field()
    transaction_id: Optional[str] = None

    @classmethod
    @verify(Schemas.room_olm_encrypted)
    def from_dict(cls, event_dict):
        content = event_dict["content"]

        ciphertext = content["ciphertext"]
        sender_key = content["sender_key"]

        tx_id = (
            event_dict["unsigned"].get("transaction_id", None)
            if "unsigned" in event_dict
            else None
        )

        return cls(event_dict, event_dict["sender"], sender_key, ciphertext, tx_id)


@dataclass
class DummyEvent(ToDeviceEvent):
    """Event containing a dummy message.

    This event type is used start a new Olm session with a device. The event
    has no content.

    Attributes:
        sender (str): The sender of the event.
        sender_key (str): The key of the sender that sent the event.

    """

    sender_key: str = field()
    sender_device: str = field()

    @classmethod
    @verify(Schemas.dummy_event)
    def from_dict(cls, event_dict, sender, sender_key):
        return cls(event_dict, sender, sender_key, event_dict["sender_device"])


@dataclass
class RoomKeyEvent(ToDeviceEvent):
    """Event containing a megolm room key that got sent to us.

    Attributes:
        sender (str): The sender of the event.
        sender_key (str): The key of the sender that sent the event.
        room_id (str): The room ID of the room to which the session key
            belongs to.
        session_id (str): The session id of the session key.
        algorithm (str): The algorithm of the session key.

    """

    sender_key: str = field()
    room_id: str = field()
    session_id: str = field()
    algorithm: str = field()

    @classmethod
    @verify(Schemas.room_key_event)
    def from_dict(cls, event_dict, sender, sender_key):
        event_dict = deepcopy(event_dict)
        event_dict.pop("keys")

        content = event_dict["content"]
        content.pop("session_key")

        return cls(
            event_dict,
            sender,
            sender_key,
            content["room_id"],
            content["session_id"],
            content["algorithm"],
        )


@dataclass
class ForwardedRoomKeyEvent(RoomKeyEvent):
    """Event containing a room key that got forwarded to us.

    Attributes:
        sender (str): The sender of the event.
        sender_key (str): The key of the sender that sent the event.
        room_id (str): The room ID of the room to which the session key
            belongs to.
        session_id (str): The session id of the session key.
        algorithm (str): The algorithm of the session key.

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
        event_dict = deepcopy(event_dict)
        content = event_dict["content"]
        content.pop("session_key")

        return cls(
            event_dict,
            sender,
            sender_key,
            content["room_id"],
            content["session_id"],
            content["algorithm"],
        )
