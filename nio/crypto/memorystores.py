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

from collections import defaultdict
from typing import DefaultDict, Dict, Iterator, List, Optional

if False:
    from .sessions import OlmDevice, InboundGroupSession, Session


class SessionStore(object):
    def __init__(self):
        # type: () -> None
        self._entries = defaultdict(list) \
            # type: DefaultDict[str, List[Session]]

    def add(self, sender_key, session):
        # type: (str, Session) -> bool
        if session in self._entries[sender_key]:
            return False

        self._entries[sender_key].append(session)
        self._entries[sender_key].sort(key=lambda x: x.use_time, reverse=True)
        return True

    def __iter__(self):
        # type: () -> Iterator[Session]
        for session_list in self._entries.values():
            for session in session_list:
                yield session

    def values(self):
        return self._entries.values()

    def items(self):
        return self._entries.items()

    def get(self, sender_key):
        # type: (str) -> Optional[Session]
        if self._entries[sender_key]:
            return self._entries[sender_key][0]

        return None

    def __getitem__(self, sender_key):
        # type: (str) -> List[Session]
        return self._entries[sender_key]


class GroupSessionStore(object):
    def __init__(self):
        self._entries = defaultdict(lambda: defaultdict(dict))

    def __iter__(self):
        # type: () -> Iterator[InboundGroupSession]
        for room_sessions in self._entries.values():
            for sender_sessions in room_sessions.values():
                for session in sender_sessions.values():
                    yield session

    def add(self, session):
        # type: (InboundGroupSession) -> bool
        room_id = session.room_id
        sender_key = session.sender_key
        if session in self._entries[room_id][sender_key].values():
            return False

        self._entries[room_id][sender_key][session.id] = session
        return True

    def get(self, room_id, sender_key, session_id):
        # type: (str, str, str) -> Optional[InboundGroupSession]
        if session_id in self._entries[room_id][sender_key]:
            return self._entries[room_id][sender_key][session_id]

        return None

    def __getitem__(self, room_id):
        # type: (str) -> DefaultDict[str, Dict[str, InboundGroupSession]]
        return self._entries[room_id]


class DeviceStore(object):
    """A store that holds olm devices in memory.

    The DeviceStore class implements the iter method, devices can be iterated
    over normaly using:

    >>> for device in device_store:
    ...    print(device.user_id, device.device_id)

    To get only non-deleted devices of a user the active_user_devices method
    can be used:

    >>> for device in device_store.active_user_devices("@bob:example.org"):
    ...    print(device.user_id, device.device_id)

    """
    def __init__(self):
        # type: () -> None
        self._entries = defaultdict(dict)  \
            # type: DefaultDict[str, Dict[str, OlmDevice]]

    def __iter__(self):
        # type: () -> Iterator[OlmDevice]
        for user_devices in self._entries.values():
            for device in user_devices.values():
                yield device

    def __getitem__(self, user_id):
        # type: (str) -> Dict[str, OlmDevice]
        return self._entries[user_id]

    def items(self):
        """List of tuples in the form (user id, dict(device_id, OlmDevice)."""
        return self._entries.items()

    def values(self):
        """List of devices in the form of a dict(device_id, OlmDevice)."""
        return self._entries.values()

    def active_user_devices(self, user_id):
        # type: (str) -> Iterator[OlmDevice]
        """Get all the non-deleted devices of a user.

        Args:
            user_id (str): The user for which we would like to get the devices
                for.

        This returns an iterator over all the non-deleted devices of the given
        user.

        """
        for device in self._entries[user_id].values():
            if not device.deleted:
                yield device

    def device_from_sender_key(self, user_id, sender_key):
        # type (str, str) -> Optional[OlmDevice]
        """Get a non-deleted device of a user with the matching sender key.

        Args:
            user_id (str): The user id of the device owner.
            sender_key (str): The encryption key that is owned by the device,
            usually a curve25519 public key.
        """
        for device in self.active_user_devices(user_id):
            if device.curve25519 == sender_key:
                return device

        return None

    @property
    def users(self):
        # type () -> List[str]
        """Get the list of users that the device store knows about."""
        return self._entries.keys()

    def devices(self, user_id):
        # type (str) -> str
        return self._entries[user_id].keys()

    def add(self, device):
        # type: (OlmDevice) -> bool
        """Add the given device to the store.

        Args:
            device (OlmDevice): The device that should be added to the store.

        Returns True if the device was added to the store, False if it already
        was in the store.
        """
        if device in self:
            return False

        self._entries[device.user_id][device.id] = device
        return True
