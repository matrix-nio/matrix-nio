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

"""Matrix Invite Events.

Events for invited rooms will have a stripped down version of their
counterparts for joined rooms.

Such events will be missing the event id and origin server timestamp.
Since all of the events in an invited room will be state events they will
never be encrypted.

These events help set up the state of an invited room so more information can
be displayed to users if they are invited to a room.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from ..schemas import Schemas
from .misc import BadEventType, verify, verify_or_none


@dataclass
class InviteEvent:
    """Matrix Event class for events in invited rooms.

    Events for invited rooms will have a stripped down version of their
    counterparts for joined rooms.

    Such events will be missing the event id and origin server timestamp.
    Since all of the events in an invited room will be state events they will
    never be encrypted.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
        sender (str): The fully-qualified ID of the user who sent this
            event.

    """

    source: Dict = field()
    sender: str = field()

    @classmethod
    @verify_or_none(Schemas.invite_event)
    def parse_event(
        cls, event_dict: Dict[Any, Any]
    ) -> Optional[Union[InviteEvent, BadEventType]]:
        """Parse a Matrix invite event and create a higher level event object.

        This function parses the type of the Matrix event and produces a higher
        level event object representing the parsed event.

        The event structure is checked for correctness and the event fields are
        type-checked. If this validation process fails for an event None will
        be returned.

        Args:
            event_dict (dict): The dictionary representation of the event.

        """
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

    @classmethod
    def from_dict(cls, parsed_dict):
        """Create an InviteEvent from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        raise NotImplementedError


@dataclass
class InviteMemberEvent(InviteEvent):
    """Class representing to an m.room.member event in an invited room.

    Attributes:
        state_key (str): The user_id this membership event relates to. In all
            cases except for when membership is join, the user ID in the sender
            attribute does not need to match the user ID in the state_key.
        membership (str): The membership state of the user. One of "invite",
            "join", "leave", "ban".
        prev_membership (str, optional): The previous membership state that
            this one is overwriting. Can be None in which case the membership
            state is assumed to have been "leave".
        content (dict): The content of the of the membership event.
        prev_content(dict, optional): The content of a previous membership
            event that this one is overwriting.

    """

    state_key: str = field()
    membership: str = field()
    prev_membership: str = field()
    content: dict = field()
    prev_content: dict = field(default_factory=dict)

    @classmethod
    @verify(Schemas.room_membership)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[InviteMemberEvent, BadEventType]:
        content = parsed_dict.pop("content")
        unsigned = parsed_dict.get("unsigned", {})
        prev_content = unsigned.get("prev_content", None)

        membership = content["membership"]
        prev_membership = prev_content.get("membership") if prev_content else None

        return cls(
            parsed_dict,
            parsed_dict["sender"],
            parsed_dict["state_key"],
            membership,
            prev_membership,
            content,
            prev_content,
        )


@dataclass
class InviteAliasEvent(InviteEvent):
    """An event informing us about which alias should be preferred.

    This is the RoomAliasEvent equivalent for invited rooms.

    Attributes:
        canonical_alias (str): The alias that is considered canonical.

    """

    canonical_alias: str = field()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(
        cls, parsed_dict: Dict[Any, Any]
    ) -> Union[InviteAliasEvent, BadEventType]:
        sender = parsed_dict["sender"]
        canonical_alias = parsed_dict["content"].get("alias")

        return cls(parsed_dict, sender, canonical_alias)


@dataclass
class InviteNameEvent(InviteEvent):
    """Event holding the name of the invited room.

    This is the RoomNameEvent equivalent for invited rooms.

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
    ) -> Union[InviteNameEvent, BadEventType]:
        sender = parsed_dict["sender"]
        canonical_alias = parsed_dict["content"]["name"]

        return cls(parsed_dict, sender, canonical_alias)
