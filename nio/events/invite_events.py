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

from typing import Any, Dict, Optional, Union

import attr

from ..schemas import Schemas
from .misc import BadEventType, verify


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
