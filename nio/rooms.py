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
                     RoomTopicEvent, RoomAvatarEvent, TypingNoticeEvent)
from .log import logger_group
from .responses import RoomSummary

logger = Logger("nio.rooms")
logger_group.add_logger(logger)

__all__ = [
    "MatrixRoom",
    "MatrixInvitedRoom",
    "MatrixUser",
]


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
        self.invited_users = dict()   # type: Dict[str, MatrixUser]
        self.names = defaultdict(list)  # type: DefaultDict[str, List[str]]
        self.encrypted = encrypted    # type: bool
        self.power_levels = PowerLevels()  # type: PowerLevels
        self.typing_users = []        # type: List[str]
        self.summary = None           # type: Optional[RoomSummary]
        self.room_avatar_url = None        # type: Optional[str]
        # yapf: enable

    @property
    def display_name(self):
        """Calculate display name for a room.

        Prefer returning the room name if it exists, falling back to
        a group-style name if not.

        Follows:
        https://matrix.org/docs/spec/client_server/r0.3.0.html#id268
        """
        if self.is_named:
            return self.named_room_name()

        return self.group_name()

    def named_room_name(self):
        """Return the name of the room, if it's a named room.

        Otherwise, return None.
        """
        if self.name:
            return self.name
        elif self.canonical_alias:
            return self.canonical_alias
        else:
            return None

    def group_name(self):
        """Return the group-style name of the room.

        In other words, a display name based on the names of room members. This
        is used for ad-hoc groups of people (usually direct chats).

        Returns None if there are no users.
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
            return None

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

    def avatar_url(self, user_id):
        # type: (str) -> Optional[str]
        """Get avatar url for a user.

        Returns a matrix content URI, or None if the user has no avatar.
        """
        if user_id not in self.users:
            return None

        return self.users[user_id].avatar_url

    @property
    def gen_avatar_url(self):
        """
        Get the calculated room's avatar url.

        Either the room's avatar if one is set, or the avatar of the
        first user that's not ourselves if the room is an unnamed group or
        has exactly two users.
        """
        if self.room_avatar_url:
            return self.room_avatar_url

        if self.is_group or len(self.users) == 2:
            user = next(
                (u for u in self.users if u != self.own_user_id),
                None
            )
            return self.avatar_url(user)

        return None

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

    def add_member(self, user_id, display_name, avatar_url, invited=False):
        # type (str, str, str, bool) -> bool
        if user_id in self.users:
            return False

        level = self.power_levels.users.get(
            user_id,
            self.power_levels.defaults.users_default,
        )

        user = MatrixUser(user_id, display_name, avatar_url, level, invited)
        self.users[user_id] = user

        if invited:
            self.invited_users[user_id] = user

        name = display_name if display_name else user_id
        self.names[name].append(user_id)

        return True

    def remove_member(self, user_id):
        # type (str) -> bool
        if user_id in self.users or user_id in self.invited_users:
            user         = self.users.pop(user_id, None)
            invited_user = self.invited_users.pop(user_id, None)

            self.names[user.name].remove((user or invited_user).user_id)
            return True

        return False

    def handle_membership(self, event):
        # type: (RoomMemberEvent) -> bool
        """Handle a membership event for the room.

        Args:
            event (RoomMemberEvent): The event that should be handled that
                updates the room state.

        Returns True if the member list of the room has changed False
        otherwise.
        """
        target_user = event.state_key
        invited     = event.membership == "invite"

        if event.membership in ("invite", "join"):
            # Add member if not already present in self.users,
            # or the member is invited but not present in self.invited_users

            if (target_user not in self.users or
                    (invited and target_user not in self.invited_users)):

                display_name = event.content.get("displayname", None)
                avatar_url   = event.content.get("avatar_url", None)

                return self.add_member(
                    target_user, display_name, avatar_url, invited,
                )

            user = self.users[target_user]

            # Handle membership change

            user.invited = invited

            if not invited and target_user in self.invited_users:
                del self.invited_users[target_user]

            # Handle profile changes

            if "displayname" in event.content:
                self.names[user.name].remove(user.user_id)
                user.display_name = event.content["displayname"]
                self.names[user.name].append(user.user_id)

            if "avatar_url" in event.content:
                user.avatar_url = event.content["avatar_url"]

            return False

        elif event.membership in ("leave", "ban"):
            return self.remove_member(target_user)

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

        elif isinstance(event, RoomAvatarEvent):
            self.room_avatar_url = event.avatar_url

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
            self.summary.invited_member_count = summary.invited_member_count

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
            joined  = self.summary.joined_member_count
            invited = self.summary.invited_member_count

            if joined is not None and invited is not None:
                return joined + invited == len(self.users)

        return True

    @property
    def member_count(self):
        if self.summary:
            joined  = self.summary.joined_member_count
            invited = self.summary.invited_member_count

            if joined is not None and invited is not None:
                return joined + invited

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
        if (event.membership == "invite"
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
    def __init__(
        self, user_id, display_name=None, avatar_url=None, power_level=0,
        invited=False,
    ):
        # yapf: disable
        self.user_id = user_id            # type: str
        self.display_name = display_name  # type: str
        self.avatar_url = avatar_url      # type: str
        self.power_level = power_level    # type: int
        self.invited = invited            # type: bool
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
