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

from typing import Any, Dict

import attr

from ..schemas import Schemas
from .misc import verify


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
