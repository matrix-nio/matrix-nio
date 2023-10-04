# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
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

"""nio Ephemeral events.

Ephemeral events are a special type of events that are not recorded in the room
history.

Ephemeral events are used for typing notifications and read receipts.

"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..schemas import Schemas
from .misc import verify_or_none


@dataclass
class EphemeralEvent:
    """Base class for ephemeral events."""

    @classmethod
    @verify_or_none(Schemas.ephemeral_event)
    def parse_event(cls, event_dict):
        """Parse an ephemeral event and create a higher level event object.

        This function parses the type of the ephemeral event and produces a
        higher level event object representing the parsed event.

        The event structure is checked for correctness and the event fields are
        type-checked. If this validation process fails for an event None will
        be returned.

        If the event has an unknown type None is returned as well.

        Args:
            event_dict (dict): The dictionary representation of the event.

        """
        if event_dict["type"] == "m.typing":
            return TypingNoticeEvent.from_dict(event_dict)
        if event_dict["type"] == "m.receipt":
            return ReceiptEvent.from_dict(event_dict)

        return None

    @classmethod
    def from_dict(cls, parsed_dict):
        """Create an Ephemeral event from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        raise NotImplementedError


@dataclass
class TypingNoticeEvent(EphemeralEvent):
    """Informs the client of the list of users currently typing in a room.

    Attributes:
        users (List): The list of user IDs typing in this room, if any.

    """

    users: List = field()

    @classmethod
    @verify_or_none(Schemas.m_typing)
    def from_dict(cls, parsed_dict):
        return cls(parsed_dict["content"]["user_ids"])


@dataclass
class Receipt:
    """Receipt of a user acknowledging an event.

    If `receipt_type` is "m.read", then it is a read receipt and shows the last
    event that a user has read.

    Attributes:
        event_id (str): the ID of the event being acknowledged
        receipt_type (str): the type of receipt being received; this is
            commonly "m.read" for read receipts.
        user_id (str): the ID of the user who is acknowledging the event.
        timestamp (int): The timestamp the receipt was sent at.
    """

    event_id: str = field()
    receipt_type: str = field()
    user_id: str = field()
    timestamp: int = field()


@dataclass
class ReceiptEvent(EphemeralEvent):
    """Informs the client of changes in the newest events seen by users.

    A ReceiptEvent can contain multiple event_ids seen by many different users.
    At the time of writing, all Receipts have a `receipt_type` of "m.read" and
    are read receipts, but this may change in the future.

    Attributes:
        receipts (List[Receipt]): The list of `Receipt`s in this event.
    """

    receipts: List[Receipt] = field()

    @classmethod
    @verify_or_none(Schemas.m_receipt)
    def from_dict(cls, parsed_dict) -> ReceiptEvent:
        event_receipts: List[Receipt] = []

        for event_id, event in parsed_dict["content"].items():
            for receipt_type, receipt in event.items():
                for user_id, user in receipt.items():
                    # Synapse pre-0.99.3 has a bug where it sends invalid
                    # ts values. https://github.com/matrix-org/synapse/issues/4898
                    if isinstance(user, dict) and "ts" in user:
                        event_receipts.append(
                            Receipt(event_id, receipt_type, user_id, user["ts"])
                        )

        return cls(event_receipts)
