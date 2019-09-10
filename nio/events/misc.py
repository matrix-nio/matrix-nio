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

from functools import wraps
from typing import Any, Dict, Optional, Union

import attr
from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from ..log import logger_group
from ..schemas import validate_json

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
        logger.warn("Error validating event: {}".format(str(e)))
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
                logger.error("Error validating event: {}".format(str(e)))
                return None

            return f(*args, **kwargs)
        return wrapper
    return decorator


@attr.s
class UnknownBadEvent(object):
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

    source = attr.ib()
    transaction_id = attr.ib(default=None, init=False)

    decrypted = attr.ib(default=False, init=False)
    verified = attr.ib(default=False, init=False)
    sender_key = attr.ib(default=None, init=False)      # type: Optional[str]
    session_id = attr.ib(default=None, init=False)      # type: Optional[str]


@attr.s
class BadEvent(object):
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

    source = attr.ib()
    event_id = attr.ib()
    sender = attr.ib()
    server_timestamp = attr.ib()
    type = attr.ib()

    decrypted = attr.ib(default=False, init=False)
    verified = attr.ib(default=False, init=False)
    sender_key = attr.ib(default=None, init=False)      # type: Optional[str]
    session_id = attr.ib(default=None, init=False)      # type: Optional[str]
    transaction_id = attr.ib(default=None, init=False)  # type: Optional[str]

    def __str__(self):
        return "Bad event of type {}, from {}.".format(self.type, self.sender)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> BadEvent
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
