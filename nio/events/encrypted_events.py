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

from typing import Optional

import attr

from ..messages import ToDeviceMessage
from ..schemas import Schemas
from .misc import verify


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
class OlmEvent(RoomEncryptedEvent):
    sender = attr.ib()
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

    def as_key_request(self, user_id, requesting_device_id, request_id=None):
        # type: (str, str, Optional[str]) -> ToDeviceMessage
        """Make a to-device message for a room key request.

        Args:
            user_id (str): The user id of the user that should receive the key
                request.

        """
        content = {
            "action": "request",
            "body": {
                "algorithm": self.algorithm,
                "session_id": self.session_id,
                "room_id": self.room_id,
                "sender_key": self.sender_key
            },
            "request_id": request_id or self.session_id,
            "requesting_device_id": requesting_device_id,
        }

        return ToDeviceMessage(
            "m.room_key_request",
            user_id,
            "*",
            content
        )
