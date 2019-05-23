# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
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

from builtins import super
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, NamedTuple, Optional

from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .events import (Event, InviteAliasEvent, InviteMemberEvent,
                     InviteNameEvent, PowerLevels, PowerLevelsEvent,
                     RoomAliasEvent, RoomCreateEvent, RoomEncryptionEvent,
                     RoomGuestAccessEvent, RoomHistoryVisibilityEvent,
                     RoomJoinRulesEvent, RoomMemberEvent, RoomNameEvent,
                     RoomTopicEvent)
from .log import logger_group
from .responses import RoomSummary, TypingNoticeEvent

logger = Logger("nio.rooms")
logger_group.add_logger(logger)


class MatrixRoom(object):
    """Represents a Matrix room."""

    def __init__(self, room_id, own_user_id, encrypted=False):
        # type: (str, str, bool) -> None
        """Initialize a MatrixRoom object."""
        # yapf: disable
        self.room_id = room_id        # type: str
        self.own_user_id = own_user_id
        self.creator = ""             # type: str
        self.federate = True          # type: bool
        self.room_version = "1"       # type: str
        self.guest_access = "forbidden"  # type: str
        self.join_rule = "invite"     # type: str
        self.history_visibility = "shared"  # type: str
        self.canonical_alias = None   # type: Optional[str]
        self.topic = None             # type: Optional[str]
        self.name = None              # type: Optional[str]
        self.users = dict()           # type: Dict[str, MatrixUser]
        self.names = defaultdict(list)  # type: DefaultDict[str, List[str]]
        self.encrypted = encrypted    # type: bool
        self.power_levels = PowerLevels()  # type: PowerLevels
        self.typing_users = []        # type: List[str]
        self.summary = None           # type: Optional[RoomSummary]
        # yapf: enable

    @property
    def display_name(self):
        """Calculate display name for a room.

        Prefer returning the room name if it exists, falling back to
        a group-style name if not.

        Mostly follows:
        https://matrix.org/docs/spec/client_server/r0.3.0.html#id268

        An exception is that we prepend '#' before the room name to make it
        visually distinct from private messages and unnamed groups of users
        ("direct chats") in weechat's buffer list.
        """
        if self.is_named:
            return self.named_room_name()
        else:
            return self.group_name()

    def named_room_name(self):
        """Return the name of the room, if it's a named room.

        Otherwise, return None.
        """
        if self.name and self.name != '#':
            return self.name if self.name.startswith('#') else '#' + self.name
        elif self.canonical_alias:
            return self.canonical_alias
        elif self.name == '#':
            return '##'
        else:
            return None

    def group_name(self):
        """Return the group-style name of the room.

        In other words, a display name based on the names of room members. This
        is used for ad-hoc groups of people (usually direct chats).
        """
        # Sort user display names, excluding our own user and using the
        # mxid as the sorting key.

        user_names = [
            self.user_name(u)
            for u in sorted(self.users.keys())
            if u != self.own_user_id
        ]
        num_users = len(user_names)

        if num_users == 1:
            return user_names[0]
        elif num_users == 2:
            return " and ".join(user_names)
        elif num_users >= 3:
            return "{first_user} and {num} others".format(
                first_user=user_names[0], num=num_users - 1
            )
        else:
            return "Empty room?"

    def user_name(self, user_id):
        """Get disambiguated display name for a user.

        Returns display name of a user if display name is unique or returns
        a display name in form "<display name> (<matrix id>)" if there is
        more than one user with same display name.
        """
        if user_id not in self.users:
            return None

        user = self.users[user_id]
        if len(self.names[user.name]) > 1:
            return user.disambiguated_name
        return user.name

    def user_name_clashes(self, name):
        """Get a list of users that have same display name."""
        return self.names[name]

    @property
    def machine_name(self):
        """Calculate an unambiguous, unique machine name for a room.

        Either use the more human-friendly canonical alias, if it exists, or
        the internal room ID if not.
        """
        if self.canonical_alias:
            return self.canonical_alias
        else:
            return self.room_id

    @property
    def is_named(self):
        """Determine whether a room is name.

        A named room is a room with either the name or a canonical alias set.
        """
        return self.canonical_alias or self.name

    @property
    def is_group(self):
        """Determine whether a room is an ad-hoc group (often a direct chat).

        A group is an unnamed room with no canonical alias.
        """
        return not self.is_named

    def add_member(self, user_id, display_name):
        if user_id in self.users:
            return

        level = self.power_levels.users.get(
            user_id,
            self.power_levels.defaults.users_default
        )

        user = MatrixUser(user_id, display_name, level)
        self.users[user_id] = user

        name = display_name if display_name else user_id
        self.names[name].append(user_id)

    def remove_member(self, user_id):
        if user_id in self.users:
            user = self.users[user_id]
            self.names[user.name].remove(user.user_id)
            del self.users[user_id]

    def handle_membership(self, event):
        # type: (RoomMemberEvent) -> bool
        """Handle a membership event for the room.

        Args:
            event (RoomMemberEvent): The event that should be handled that
                updates the room state.

        Returns True if the member list of the room has changed False
        otherwise.
        """
        if event.content["membership"] == "join":
            if event.state_key not in self.users:
                display_name = event.content.get("displayname", None)
                return self.add_member(event.state_key, display_name)

            # Handle profile changes
            user = self.users[event.sender]
            if "displayname" in event.content:
                self.names[user.name].remove(user.user_id)
                user.display_name = event.content["displayname"]
                self.names[user.name].append(user.user_id)
                return False

        elif event.content["membership"] in ["leave", "ban"]:
            return self.remove_member(event.state_key)

        elif event.content["membership"] == "invite":
            pass

        return False

    def handle_ephemeral_event(self, event):
        if isinstance(event, TypingNoticeEvent):
            self.typing_users = event.users

    def handle_event(self, event):
        # type: (Event) -> None
        logger.info(
            "Room {} handling event of type {}".format(
                self.room_id, type(event).__name__
            )
        )

        if isinstance(event, RoomCreateEvent):
            self.creator = event.creator
            self.federate = event.federate
            self.room_version = event.room_version

        elif isinstance(event, RoomGuestAccessEvent):
            self.guest_access = event.guest_access

        elif isinstance(event, RoomHistoryVisibilityEvent):
            self.history_visibility = event.history_visibility

        elif isinstance(event, RoomJoinRulesEvent):
            self.join_rule = event.join_rule

        elif isinstance(event, RoomNameEvent):
            self.name = event.name

        elif isinstance(event, RoomAliasEvent):
            self.canonical_alias = event.canonical_alias

        elif isinstance(event, RoomTopicEvent):
            self.topic = event.topic

        elif isinstance(event, RoomEncryptionEvent):
            self.encrypted = True

        elif isinstance(event, PowerLevelsEvent):
            self.power_levels.update(event.power_levels)

            # Update the power levels of the joined users
            for user_id, level in self.power_levels.users.items():
                if user_id in self.users:
                    logger.info(
                        "Changing power level for user {} from {} to "
                        "{}".format(
                            user_id, self.users[user_id].power_level, level
                        )
                    )
                    self.users[user_id].power_level = level

    def update_summary(self, summary):
        if not self.summary:
            self.summary = summary
            return

        if summary.joined_member_count:
            self.summary.joined_member_count = summary.joined_member_count

        if summary.invited_member_count:
            self.summary.invited_member_count = summary.joined_member_count

        if summary.heroes:
            self.summary.heroes = summary.heroes

    @property
    def members_synced(self):
        # type: () -> bool
        """Check if the room member state is fully synced.

        Room members can be missing from the room if syncs are done using lazy
        member loading, the room summary will contain the full member count but
        other member info will be missing.

        A `joined_members` request should be done for this room to populate the
        member list. This is crucial for encrypted rooms before sending any
        messages.
        """
        if self.summary:
            if self.summary.joined_member_count is not None:
                return self.summary.joined_member_count == len(self.users)

        return True

    @property
    def member_count(self):
        if self.summary:
            return self.summary.joined_member_count or len(self.users)

        return len(self.users)


class MatrixInvitedRoom(MatrixRoom):
    def __init__(self, room_id, own_user_id):
        # type: (str, str) -> None
        self.inviter = None  # type: Optional[str]
        super().__init__(room_id, own_user_id)

    def handle_membership(self, event):
        # type: (RoomMemberEvent) -> bool
        """Handle a membership event for the invited room.

        Args:
            event (RoomMemberEvent): The event that should be handled that
                updates the room state.

        Returns True if the member list of the room has changed False
        otherwise.
        """
        if (event.content["membership"] == "invite"
                and event.state_key == self.own_user_id):
            self.inviter = event.sender

        return super().handle_membership(event)

    def handle_event(self, event):
        # type: (Event) -> None
        logger.info(
            "Room {} handling event of type {}".format(
                self.room_id, type(event).__name__
            )
        )

        if isinstance(event, InviteMemberEvent):
            self.handle_membership(event)

        elif isinstance(event, InviteNameEvent):
            self.name = event.name

        elif isinstance(event, InviteAliasEvent):
            self.canonical_alias = event.canonical_alias


class MatrixUser(object):
    def __init__(self, user_id, display_name=None, power_level=0):
        # yapf: disable
        self.user_id = user_id            # type: str
        self.display_name = display_name  # type: str
        self.power_level = power_level    # type: int
        # yapf: enable

    @property
    def name(self):
        if self.display_name:
            return self.display_name
        return self.user_id

    @property
    def disambiguated_name(self):
        # as per https://matrix.org/docs/spec/client_server/r0.4.0.html#id346
        if self.display_name:
            return "{name} ({user_id})".format(name=self.display_name,
                                               user_id=self.user_id)
        return self.user_id
