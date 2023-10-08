# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2021 Famedly GmbH
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

from __future__ import annotations

import logging
from collections import defaultdict
from typing import DefaultDict, Dict, List, Optional, Set, Tuple, Union

from .events import (
    AccountDataEvent,
    EphemeralEvent,
    Event,
    FullyReadEvent,
    InviteAliasEvent,
    InviteMemberEvent,
    InviteNameEvent,
    PowerLevels,
    PowerLevelsEvent,
    Receipt,
    ReceiptEvent,
    RoomAliasEvent,
    RoomAvatarEvent,
    RoomCreateEvent,
    RoomEncryptionEvent,
    RoomGuestAccessEvent,
    RoomHistoryVisibilityEvent,
    RoomJoinRulesEvent,
    RoomMemberEvent,
    RoomNameEvent,
    RoomSpaceChildEvent,
    RoomSpaceParentEvent,
    RoomTopicEvent,
    RoomUpgradeEvent,
    TagEvent,
    TypingNoticeEvent,
)
from .responses import RoomSummary, UnreadNotifications

logger = logging.getLogger(__name__)

__all__ = [
    "MatrixRoom",
    "MatrixInvitedRoom",
    "MatrixUser",
]


class MatrixRoom:
    """Represents a Matrix room."""

    def __init__(self, room_id: str, own_user_id: str, encrypted: bool = False) -> None:
        """Initialize a MatrixRoom object."""
        # yapf: disable
        self.room_id: str = room_id
        self.own_user_id = own_user_id
        self.creator: str = ""
        self.federate: bool = True
        self.room_version: str = "1"
        self.room_type: Optional[str] = None
        self.guest_access: str = "forbidden"
        self.join_rule: str = "invite"
        self.history_visibility: str = "shared"
        self.canonical_alias: Optional[str] = None
        self.topic: Optional[str] = None
        self.name: Optional[str] = None
        self.parents: Set[str] = set()
        self.children: Set[str] = set()
        self.users: Dict[str, MatrixUser] = {}
        self.invited_users: Dict[str, MatrixUser] = {}
        self.names: DefaultDict[str, List[str]] = defaultdict(list)
        self.encrypted: bool = encrypted
        self.power_levels: PowerLevels = PowerLevels()
        self.typing_users: List[str] = []
        self.read_receipts: Dict[str, Receipt] = {}
        self.summary: Optional[RoomSummary] = None
        self.room_avatar_url: Optional[str] = None
        self.fully_read_marker: Optional[str] = None
        self.tags: Dict[str, Optional[Dict[str, float]]] = {}
        self.unread_notifications: int = 0
        self.unread_highlights: int = 0
        self.members_synced: bool = False
        self.replacement_room: Union[str, None] = None
        # yapf: enable

    @property
    def display_name(self) -> str:
        """Calculate display name for a room.

        Prefer returning the room name if it exists, falling back to
        a group-style name if not.

        Follows:
        https://matrix.org/docs/spec/client_server/r0.6.0#id342
        """
        return self.named_room_name() or self.group_name()

    def named_room_name(self) -> Optional[str]:
        """Return the name of the room if it's a named room, otherwise None."""
        return self.name or self.canonical_alias or None

    def group_name(self) -> str:
        """Return the group-style name of the room.

        In other words, a display name based on the names of room members. This
        is used for ad-hoc groups of people (usually direct chats).
        """

        empty, user_ids, others = self.group_name_structure()

        names = [self.user_name(u) or u for u in user_ids]

        if others:
            text = f"{', '.join(names)} and {others} other{'' if others == 1 else 's'}"
        elif len(names) == 0:
            text = ""
        elif len(names) == 1:
            text = names[0]
        else:
            text = f"{', '.join(names[:-1])} and {names[-1]}"

        if empty and text:
            text = f"Empty Room (had {text})"
        elif empty:
            text = "Empty Room"

        return text

    def group_name_structure(self) -> Tuple[bool, List[str], int]:
        """Get if room is empty, ID for listed users and the N others count."""
        try:
            heroes, joined, invited = self._summary_details()
        except ValueError:
            users = [
                u
                for u in sorted(self.users, key=lambda u: self.user_name(u))
                if u != self.own_user_id
            ]
            empty = not users

            if len(users) <= 5:
                return (empty, users, 0)

            return (empty, users[:5], len(users) - 5)

        empty = self.member_count <= 1

        if len(heroes) >= self.member_count - 1:
            return (empty, heroes, 0)

        return (empty, heroes, self.member_count - 1 - len(heroes))

    def user_name(self, user_id: str) -> Optional[str]:
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

    def user_name_clashes(self, name: str) -> List[str]:
        """Get a list of users that have same display name."""
        return self.names[name]

    def avatar_url(self, user_id: str) -> Optional[str]:
        """Get avatar url for a user.

        Returns a matrix content URI, or None if the user has no avatar.
        """
        if user_id not in self.users:
            return None

        return self.users[user_id].avatar_url

    @property
    def gen_avatar_url(self) -> Optional[str]:
        """
        Get the calculated room's avatar url.

        Either the room's avatar if one is set, or the avatar of the
        first user that's not ourselves if the room is an unnamed group or
        has exactly two users.
        """
        if self.room_avatar_url:
            return self.room_avatar_url

        try:
            heroes, _, _ = self._summary_details()
        except ValueError:
            if self.is_group and len(self.users) == 2:
                return self.avatar_url(
                    next(
                        u
                        for u in sorted(self.users, key=lambda u: self.user_name(u))
                        if u != self.own_user_id
                    )
                )
            return None

        if self.is_group and self.member_count == 2 and len(heroes) >= 1:
            return self.avatar_url(heroes[0])

        return None

    @property
    def machine_name(self) -> str:
        """Calculate an unambiguous, unique machine name for a room.

        Either use the more human-friendly canonical alias, if it exists, or
        the internal room ID if not.
        """
        return self.canonical_alias or self.room_id

    @property
    def is_named(self) -> bool:
        """Determine whether a room is named.

        A named room is a room with either the name or a canonical alias set.
        """
        return bool(self.canonical_alias or self.name)

    @property
    def is_group(self) -> bool:
        """Determine whether a room is an ad-hoc group (often a direct chat).

        A group is an unnamed room with no canonical alias.
        """
        return not self.is_named

    def add_member(
        self,
        user_id: str,
        display_name: Optional[str],
        avatar_url: Optional[str],
        invited: bool = False,
    ) -> bool:
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

    def remove_member(self, user_id: str) -> bool:
        user = self.users.pop(user_id, None)

        if user:
            self.names[user.name].remove(user.user_id)

        invited_user = self.invited_users.pop(user_id, None)

        if invited_user:
            try:
                self.names[invited_user.name].remove(invited_user.user_id)
            except ValueError:
                pass

        return bool(user or invited_user)

    def handle_membership(
        self,
        event: Union[RoomMemberEvent, InviteMemberEvent],
    ) -> bool:
        """Handle a membership event for the room.

        Args:
            event (RoomMemberEvent): The event that should be handled that
                updates the room state.

        Returns True if the member list of the room has changed False
        otherwise.
        """
        target_user = event.state_key
        invited = event.membership == "invite"

        if event.membership in ("invite", "join"):
            # Add member if not already present in self.users,
            # or the member is invited but not present in self.invited_users

            if target_user not in self.users or (
                invited and target_user not in self.invited_users
            ):
                display_name = event.content.get("displayname", None)
                avatar_url = event.content.get("avatar_url", None)

                return self.add_member(
                    target_user,
                    display_name,
                    avatar_url,
                    invited,
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

    def handle_ephemeral_event(self, event: EphemeralEvent) -> None:
        if isinstance(event, TypingNoticeEvent):
            self.typing_users = event.users

        if isinstance(event, ReceiptEvent):
            read_receipts = filter(lambda x: x.receipt_type == "m.read", event.receipts)

            for read_receipt in read_receipts:
                self.read_receipts[read_receipt.user_id] = read_receipt

    def handle_event(self, event: Event) -> None:
        logger.info(
            f"Room {self.room_id} handling event of type {type(event).__name__}"
        )

        if isinstance(event, RoomCreateEvent):
            self.creator = event.creator
            self.federate = event.federate
            self.room_version = event.room_version
            self.room_type = event.room_type

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

        elif isinstance(event, RoomUpgradeEvent):
            self.replacement_room = event.replacement_room

        elif isinstance(event, PowerLevelsEvent):
            self.power_levels.update(event.power_levels)

            # Update the power levels of the joined users
            for user_id, level in self.power_levels.users.items():
                if user_id in self.users:
                    logger.info(
                        f"Changing power level for user {user_id} from {self.users[user_id].power_level} to {level}"
                    )
                    self.users[user_id].power_level = level

        elif isinstance(event, RoomSpaceParentEvent):
            if "via" in event.source.get("content", {}):
                self.parents.add(event.state_key)
            else:
                self.parents.discard(event.state_key)

        elif isinstance(event, RoomSpaceChildEvent):
            if "via" in event.source.get("content", {}):
                self.children.add(event.state_key)
            else:
                self.children.discard(event.state_key)

    def handle_account_data(self, event: AccountDataEvent) -> None:
        if isinstance(event, FullyReadEvent):
            self.fully_read_marker = event.event_id

        if isinstance(event, TagEvent):
            self.tags = event.tags

    def update_unread_notifications(self, unread: UnreadNotifications) -> None:
        if unread.notification_count is not None:
            self.unread_notifications = unread.notification_count

        if unread.highlight_count is not None:
            self.unread_highlights = unread.highlight_count

    def update_summary(self, summary: RoomSummary) -> None:
        if not self.summary:
            self.summary = summary
            return

        if summary.joined_member_count is not None:
            self.summary.joined_member_count = summary.joined_member_count

        if summary.invited_member_count is not None:
            self.summary.invited_member_count = summary.invited_member_count

        if summary.heroes is not None:
            self.summary.heroes = summary.heroes

    def _summary_details(self) -> Tuple[List[str], int, int]:
        """Return the summary attributes if it can be used for calculations."""
        valid = bool(
            self.summary is not None
            and self.summary.joined_member_count is not None
            and self.summary.invited_member_count is not None,
        )
        if not valid:
            raise ValueError("Unusable summary")

        return (  # type: ignore
            self.summary.heroes or [],  # type: ignore
            self.summary.joined_member_count,  # type: ignore
            self.summary.invited_member_count,  # type: ignore
        )

    @property
    def joined_count(self) -> int:
        try:
            return self._summary_details()[1]
        except ValueError:
            return len(tuple(u for u in self.users.values() if not u.invited))

    @property
    def invited_count(self) -> int:
        try:
            return self._summary_details()[2]
        except ValueError:
            return len(tuple(u for u in self.users.values() if u.invited))

    @property
    def member_count(self) -> int:
        try:
            _, joined, invited = self._summary_details()
        except ValueError:
            return len(self.users)

        return joined + invited


class MatrixInvitedRoom(MatrixRoom):
    def __init__(self, room_id: str, own_user_id: str) -> None:
        self.inviter: Optional[str] = None
        super().__init__(room_id, own_user_id)

    def handle_membership(
        self,
        event: Union[RoomMemberEvent, InviteMemberEvent],
    ) -> bool:
        """Handle a membership event for the invited room.

        Args:
            event (RoomMemberEvent): The event that should be handled that
                updates the room state.

        Returns True if the member list of the room has changed False
        otherwise.
        """
        if event.membership == "invite" and event.state_key == self.own_user_id:
            self.inviter = event.sender

        return super().handle_membership(event)

    def handle_event(self, event: Event) -> None:
        logger.info(
            f"Room {self.room_id} handling event of type {type(event).__name__}"
        )

        if isinstance(event, InviteMemberEvent):
            self.handle_membership(event)

        elif isinstance(event, InviteNameEvent):
            self.name = event.name

        elif isinstance(event, InviteAliasEvent):
            self.canonical_alias = event.canonical_alias


class MatrixUser:
    def __init__(
        self,
        user_id: str,
        display_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        power_level: int = 0,
        invited: bool = False,
        presence: str = "offline",
        last_active_ago: Optional[int] = None,
        currently_active: Optional[bool] = None,
        status_msg: Optional[str] = None,
    ):
        # yapf: disable
        self.user_id = user_id
        self.display_name = display_name
        self.avatar_url = avatar_url
        self.power_level = power_level
        self.invited = invited
        self.presence = presence
        self.last_active_ago = last_active_ago
        self.currently_active = currently_active
        self.status_msg = status_msg
        # yapf: enable

    @property
    def name(self) -> str:
        return self.display_name or self.user_id

    @property
    def disambiguated_name(self) -> str:
        # as per https://matrix.org/docs/spec/client_server/r0.4.0.html#id346
        if self.display_name:
            return f"{self.display_name} ({self.user_id})"
        return self.user_id
