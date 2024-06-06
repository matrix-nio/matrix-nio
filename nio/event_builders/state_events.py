# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2019 miruka <miruka@disroot.org>
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

"""Matrix state events module.

This module contains classes that can be used to easily create
room state event dicts.

For example, to turn on encryption in a room with the ``HttpClient`` or
``AsyncClient``, the ``EnableEncryptionBuilder`` class can be used:

    >>> event_dict = EnableEncryptionBuilder().as_dict()
    >>> client.room_send(
    ...     room_id      = "!test:example.com",
    ...     message_type = event_dict["type"],
    ...     content      = event_dict["content"],
    ... )
"""

from dataclasses import dataclass, field

from . import EventBuilder


@dataclass
class EnableEncryptionBuilder(EventBuilder):
    """A state event sent to enable encryption in a room.

    Attributes:
        algorithm (str): The algorithm to use for encrypting messages.
            The default ``m.megolm.v1.aes-sha2`` should not be changed.

        rotation_ms (int): How long in milliseconds an encrypted session
            should be used before changing it.
            The default ``604800000`` (a week) is recommended.

        rotation_msgs (int): How many messages can be received in a room before
            changing the encrypted session.
            The default ``100`` is recommended.

    """

    algorithm: str = "m.megolm.v1.aes-sha2"
    rotation_ms: int = 604800000
    rotation_msgs: int = 100

    def as_dict(self):
        return {
            "type": "m.room.encryption",
            "state_key": "",
            "content": {
                "algorithm": self.algorithm,
                "rotation_period_ms": self.rotation_ms,
                "rotation_period_msgs": self.rotation_msgs,
            },
        }


@dataclass
class ChangeNameBuilder(EventBuilder):
    """A state event sent to change a room's name.

    Attributes:
        name (str): The name to set. Must not exceed 255 characters.
            Can be empty to remove the room's name.
    """

    name: str = field()

    def __post_init__(self):
        if len(self.name) > 255:
            raise ValueError(
                f"Room name exceeds 255 characters: {self.name}",
            )

    def as_dict(self):
        return {
            "type": "m.room.name",
            "state_key": "",
            "content": {"name": self.name},
        }


@dataclass
class ChangeTopicBuilder(EventBuilder):
    """A state event sent to change a room's topic.

    Attributes:
        topic (str): The topic to set. Can be empty to remove the room's topic.
    """

    topic: str = field()

    def as_dict(self):
        return {
            "type": "m.room.topic",
            "state_key": "",
            "content": {"topic": self.topic},
        }


@dataclass
class ChangeJoinRulesBuilder(EventBuilder):
    """A state event sent to change who can join a room.

    Attributes:
        rule (str): Can be ``public``, meaning any user can join;
            or ``invite``, meaning users must be invited to join the room.
            The matrix specification also reserves ``knock`` and ``private``
            rules, which are currently not implemented.
    """

    rule: str = field()

    def as_dict(self):
        return {
            "type": "m.room.join_rules",
            "state_key": "",
            "content": {"join_rule": self.rule},
        }


@dataclass
class ChangeGuestAccessBuilder(EventBuilder):
    """A state event sent to allow or forbid guest accounts in a room.

    Attributes:
        access (str): Whether guests can join the room.
            Can be ``can_join`` or ``forbidden``.
    """

    access: str = field()

    def as_dict(self):
        return {
            "type": "m.room.guest_access",
            "state_key": "",
            "content": {"guest_access": self.access},
        }


@dataclass
class ChangeHistoryVisibilityBuilder(EventBuilder):
    """A state event sent to set what can users see from the room history.

    Attributes:
        visibility (str): Can be:
            - ``invited``: users can't see events that happened before they
                were invited to the room

            - ``joined``: users can't see events that happened before they
                joined or accepted an invitation to the room.

            - ``shared``: users that joined the room can see the entire
                room's history

            - ``world_readable``: anyone can see the entire room's history,
                including users that aren't part of the room.
    """

    visibility: str = field()

    def as_dict(self):
        return {
            "type": "m.room.history_visibility",
            "state_key": "",
            "content": {"history_visibility": self.visibility},
        }


# TODO: power_levels, canonical_alias, avatar, pinned_events
