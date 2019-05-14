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

from typing import Any, Dict, List, Optional, Union

import attr

from ..schemas import Schemas
from .encrypted_events import RoomEncryptedEvent
from .misc import BadEventType, verify


@attr.s
class ToDeviceEvent(object):
    source = attr.ib()
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

        return None


@attr.s
class KeyVerificationEvent(ToDeviceEvent):
    transaction_id = attr.ib(type=str)


@attr.s
class KeyVerificationStart(KeyVerificationEvent):
    from_device = attr.ib(type=str)
    method = attr.ib(type=str)
    key_agreement_protocols = attr.ib(type=List[str])
    hashes = attr.ib(type=List[str])
    message_authentication_codes = attr.ib(type=List[str])
    short_authentication_string = attr.ib(type=List[str])

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


@attr.s
class KeyVerificationAccept(KeyVerificationEvent):
    commitment = attr.ib(type=str)
    key_agreement_protocol = attr.ib(type=str)
    hash = attr.ib(type=str)
    message_authentication_code = attr.ib(type=str)
    short_authentication_string = attr.ib(type=List[str])

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


@attr.s
class KeyVerificationKey(KeyVerificationEvent):
    key = attr.ib(type=str)

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


@attr.s
class KeyVerificationMac(KeyVerificationEvent):
    mac = attr.ib(type=Dict[str, str])
    keys = attr.ib(type=str)

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


@attr.s
class KeyVerificationCancel(KeyVerificationEvent):
    code = attr.ib(type=str)
    reason = attr.ib(type=str)

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
