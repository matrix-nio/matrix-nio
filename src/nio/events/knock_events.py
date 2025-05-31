# Copyright © 2025-2025 Jonas Jelten <jj@sft.lol>
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

"""Matrix Knock Events.

Events for knocked rooms will have a stripped down version of their
counterparts for joined rooms.

Such events will be missing the event id and origin server timestamp.
Since all of the events in an knocked room will be state events they will
never be encrypted.

These events help set up the state of a knocked room so more information can
be displayed to users if they knocked a room.
"""

from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Optional, Type, Union

from ..schemas import Schemas
from .misc import BadEventType, verify, verify_or_none
from .room_events import RoomEvent


@dataclass
class KnockEvent(RoomEvent):
    """Matrix "stripped state" event class for events in knocked rooms.

    Events for knocked rooms will have a stripped down version of their
    counterparts for knocked rooms.

    Such events will be missing the event id and origin server timestamp.
    Since all of the events in a knocked room will be state events they will
    never be encrypted.

    Attributes:
        source (dict): The source dictionary of the event. This allows access
            to all the event fields in a non-secure way.
        sender (str): The fully-qualified ID of the user who sent this
            event.

    """

    @classmethod
    @verify_or_none(Schemas.stripped_state_event)
    def parse_event(
        cls, event_dict: Dict
    ) -> Optional[Union[KnockEvent, BadEventType]]:
        """Parse a Matrix knock event and create a higher level event object.

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
            return KnockMemberEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.canonical_alias":
            return KnockAliasEvent.from_dict(event_dict)
        elif event_dict["type"] == "m.room.name":
            return KnockNameEvent.from_dict(event_dict)

        return None

    @classmethod
    @abstractmethod
    def from_dict(cls: Type[KnockEvent], parsed_dict: Dict):
        """Create an KnockEvent from a dictionary.

        Args:
            parsed_dict (dict): The dictionary representation of the event.

        """
        raise NotImplementedError


@dataclass
class KnockMemberEvent(KnockEvent):
    """Class representing to an m.room.member event in a knocked room.

    Attributes:
        state_key (str): The user_id this membership event relates to. In all
            cases except for when membership is join, the user ID in the sender
            attribute does not need to match the user ID in the state_key.
        membership (str): The membership state of the user. One of "invite",
            "join", "leave", "ban", "knock".
        prev_membership (str, optional): The previous membership state that
            this one is overwriting. Can be None in which case the membership
            state is assumed to have been "leave".
        content (dict): The content of the of the membership event.
        prev_content(dict, optional): The content of a previous membership
            event that this one is overwriting.

    """

    state_key: str = field()
    membership: str = field()
    prev_membership: Optional[str] = field()
    content: dict = field()
    prev_content: dict = field(default_factory=dict)

    @classmethod
    @verify(Schemas.room_membership)
    def from_dict(
        cls, parsed_dict: Dict
    ) -> Union[KnockMemberEvent, BadEventType]:
        content = parsed_dict.pop("content")
        unsigned = parsed_dict.get("unsigned", {})
        prev_content = unsigned.get("prev_content", None)

        membership = content["membership"]
        prev_membership = prev_content.get("membership") if prev_content else None

        return cls(
            parsed_dict,
            parsed_dict["state_key"],
            membership,
            prev_membership,
            content,
            prev_content,
        )


@dataclass
class KnockAliasEvent(KnockEvent):
    """An event informing us about which alias should be preferred.

    This is the RoomAliasEvent equivalent for invited rooms.

    Attributes:
        canonical_alias (str): The alias that is considered canonical.

    """

    canonical_alias: str = field()

    @classmethod
    @verify(Schemas.room_canonical_alias)
    def from_dict(
        cls, parsed_dict: Dict
    ) -> Union[KnockAliasEvent, BadEventType]:
        canonical_alias = parsed_dict["content"].get("alias")

        return cls(parsed_dict, canonical_alias)


@dataclass
class KnockNameEvent(KnockEvent):
    """Event holding the name of the knocked room.

    This is the RoomNameEvent equivalent for knocked rooms.

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
        cls, parsed_dict: Dict
    ) -> Union[KnockNameEvent, BadEventType]:
        canonical_alias = parsed_dict["content"]["name"]

        return cls(parsed_dict, canonical_alias)
