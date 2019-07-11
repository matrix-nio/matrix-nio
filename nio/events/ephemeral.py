# -*- coding: utf-8 -*-

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

from typing import List

import attr

from ..schemas import Schemas
from .misc import verify_or_none


@attr.s
class EphemeralEvent(object):
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

        return None

    @classmethod
    def from_dict(cls, parsed_dict):
        """Create an Ephemeral event from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        raise NotImplementedError()


@attr.s
class TypingNoticeEvent(EphemeralEvent):
    """Informs the client of the list of users currently typing in a room.

    Attributes:
        users (List): The list of user IDs typing in this room, if any.

    """

    users = attr.ib(type=List)

    @classmethod
    @verify_or_none(Schemas.m_typing)
    def from_dict(cls, parsed_dict):
        return cls(parsed_dict["content"]["user_ids"])
