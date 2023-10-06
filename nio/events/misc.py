from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Dict, Optional, Union

from jsonschema.exceptions import SchemaError, ValidationError

from ..schemas import validate_json

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


logger = logging.getLogger(__name__)


def validate_or_badevent(
    parsed_dict: Dict[Any, Any],
    schema: Dict[Any, Any],
) -> Optional[Union[BadEvent, UnknownBadEvent]]:
    try:
        validate_json(parsed_dict, schema)
    except (ValidationError, SchemaError) as e:
        logger.warning(f"Error validating event: {str(e)}")
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


def verify_or_none(schema):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            event_dict = args[1]

            try:
                validate_json(event_dict, schema)
            except (ValidationError, SchemaError) as e:
                logger.error(f"Error validating event: {str(e)}")
                return None

            return f(*args, **kwargs)

        return wrapper

    return decorator


@dataclass
class UnknownBadEvent:
    """An event that doesn't have the minimal necessary structure.

    This type of event will be created if we can't find the event_id, sender,
    origin server timestamp or event type.

    The event can still be inspected with the source attribute.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
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
    transaction_id: Optional[str] = None

    decrypted: bool = field(default=False, init=False)
    verified: bool = field(default=False, init=False)
    sender_key: Optional[str] = field(default=None, init=False)
    session_id: Optional[str] = field(default=None, init=False)


@dataclass
class BadEvent:
    """An event that failed event schema and type validation.

    This type of event will be created if the event has a valid core structure
    but failed validation for the given event type.

    The event can still be inspected with the source attribute.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
        event_id (str): A globally unique event identifier.
        sender (str): The fully-qualified ID of the user who sent this
            event.
        server_timestamp (int): Timestamp in milliseconds on originating
            homeserver when this event was sent.
        type (str): The claimed type of the event.
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
    event_id: str = field()
    sender: str = field()
    server_timestamp: int = field()
    type: str = field()

    decrypted: bool = field(default=False, init=False)
    verified: bool = field(default=False, init=False)
    sender_key: Optional[str] = field(default=None, init=False)
    session_id: Optional[str] = field(default=None, init=False)
    transaction_id: Optional[str] = field(default=None, init=False)

    def __str__(self):
        return f"Bad event of type {self.type}, from {self.sender}."

    @classmethod
    def from_dict(cls, parsed_dict: Dict[Any, Any]) -> BadEvent:
        timestamp = parsed_dict["origin_server_ts"]

        timestamp = timestamp if timestamp > 0 else 0
        return cls(
            parsed_dict,
            parsed_dict["event_id"],
            parsed_dict["sender"],
            timestamp,
            parsed_dict["type"],
        )


BadEventType = Union[BadEvent, UnknownBadEvent]
