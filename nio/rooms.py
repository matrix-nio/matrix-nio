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
from typing import Any, Dict, NamedTuple, Optional, List

from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .events import (
    Event,
    InviteAliasEvent,
    InviteMemberEvent,
    InviteNameEvent,
    PowerLevels,
    PowerLevelsEvent,
    RoomAliasEvent,
    RoomEncryptionEvent,
    RoomMemberEvent,
    RoomNameEvent,
    RoomTopicEvent,
)

from .responses import TypingNoticeEvent
from .log import logger_group

logger = Logger("nio.rooms")
logger_group.add_logger(logger)


class MatrixRoom(object):
    def __init__(self, room_id, own_user_id):
        # type: (str, str) -> None
        # yapf: disable
        self.room_id = room_id        # type: str
        self.own_user_id = own_user_id
        self.canonical_alias = None   # type: Optional[str]
        self.name = None              # type: Optional[str]
        self.users = dict()           # type: Dict[str, MatrixUser]
        self.encrypted = False        # type: bool
        self.power_levels = PowerLevels()  # type: PowerLevels
        self.typing_users = []        # type: List[str]
        # yapf: enable

    def display_name(self):
        """
        Calculate display name for a room.

        Prefer returning the room name if it exists, falling back to
        a group-style name if not.

        Mostly follows:
        https://matrix.org/docs/spec/client_server/r0.3.0.html#id268

        An exception is that we prepend '#' before the room name to make it
        visually distinct from private messages and unnamed groups of users
        ("direct chats") in weechat's buffer list.
        """
        if self.is_named():
            return self.named_room_name()
        else:
            return self.group_name()

    def named_room_name(self):
        """
        Returns the name of the room, if it's a named room. Otherwise return
        None.
        """
        if self.name:
            return "#" + self.name
        elif self.canonical_alias:
            return self.canonical_alias
        else:
            return None

    def group_name(self):
        """
        Returns the group-style name of the room, i.e. a name based on the room
        members.
        """
        # Sort user display names, excluding our own user and using the
        # mxid as the sorting key.
        #
        # TODO: Hook the user display name disambiguation algorithm here.
        # Currently, we use the user display names as is, which may not be
        # unique.
        users = [
            user.user_id
            for mxid, user in sorted(self.users.items(), key=lambda t: t[0])
            if mxid != self.own_user_id
        ]

        num_users = len(users)

        if num_users == 1:
            return users[0]
        elif num_users == 2:
            return " and ".join(users)
        elif num_users >= 3:
            return "{first_user} and {num} others".format(
                first_user=users[0], num=num_users - 1
            )
        else:
            return "Empty room?"

    def machine_name(self):
        """
        Calculate an unambiguous, unique machine name for a room.

        Either use the more human-friendly canonical alias, if it exists, or
        the internal room ID if not.
        """
        if self.canonical_alias:
            return self.canonical_alias
        else:
            return self.room_id

    def is_named(self):
        """
        Is this a named room?

        A named room is a room with either the name or a canonical alias set.
        """
        return self.canonical_alias or self.name

    def is_group(self):
        """
        Is this an ad hoc group of users?

        A group is an unnamed room with no canonical alias.
        """
        return not self.is_named()

    def add_member(self, user_id, display_name):
        if user_id in self.users:
            return

        level = self.power_levels.users.get(
            user_id,
            self.power_levels.defaults.users_default
        )

        user = MatrixUser(user_id, display_name, level)
        self.users[user_id] = user

    def _handle_membership(self, event):
        # type: (Any) -> None
        def join(event):
            display_name = event.content.get("displayname", None)
            self.add_member(event.state_key, display_name)
            return

        if event.content["membership"] == "join":
            if event.state_key not in self.users:
                join(event)
            else:
                # Handle profile changes
                user = self.users[event.sender]
                if "displayname" in event.content:
                    user.display_name = event.content["displayname"]

        elif event.content["membership"] == "leave":
            if event.state_key in self.users:
                del self.users[event.state_key]
                return

        elif event.content["membership"] == "invite":
            pass

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

        if isinstance(event, RoomMemberEvent):
            self._handle_membership(event)

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


class MatrixInvitedRoom(MatrixRoom):
    def __init__(self, room_id, own_user_id):
        # type: (str, str) -> None
        self.inviter = None  # type: Optional[str]
        super().__init__(room_id, own_user_id)

    def _handle_membership(self, event):
        # type: (Any) -> None
        if (
            event.content["membership"] == "invite"
            and event.state_key == self.own_user_id
        ):
            self.inviter = event.sender
        else:
            super()._handle_membership(event)

    def handle_event(self, event):
        # type: (Event) -> None
        logger.info(
            "Room {} handling event of type {}".format(
                self.room_id, type(event).__name__
            )
        )

        if isinstance(event, InviteMemberEvent):
            self._handle_membership(event)

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
