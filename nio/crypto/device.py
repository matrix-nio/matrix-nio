# Copyright © 2020 Damir Jelić <poljar@termina.org.uk>
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
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import DefaultDict, Dict, Iterator, KeysView, Optional


# TODO document the values better.
class TrustState(Enum):
    """The device trust state.

    An Enum holding differing values that a device trust state can be in.
    """

    unset = 0
    verified = 1
    blacklisted = 2
    ignored = 3


@dataclass
class OlmDevice:
    """Class holding info about users Olm devices.

    OlmDevices represent user devices with which we can communicate in an
    encrypted manner. To do so an OlmDevice needs to have its trust state set.
    The trust state can be set to one of "verified", "ignored", or
    "blacklisted".

    Note that the trust state should never be moddified directly on an
    OlmDevice, all the attributes here are read only.

    The trust state can be changed by passing the OlmDevice to a nio Client or
    a MatrixStore class.

    Attributes:
        user_id (str): The id of the user that the device belongs to.
        device_id (str): The device id that combined with the user id uniquely
            identifies the device.
        keys (Dict): A dictionary containing the type and the public part
            of this devices encryption keys.
        display_name (str): The human readable name of this device.
        deleted (bool): A boolean signaling if this device has been deleted by
            its owner.
        trust_state (TrustState): The trust state of this device.

    """

    user_id: str = field()
    device_id: str = field()
    keys: Dict[str, str] = field()
    display_name: str = ""
    deleted: bool = False
    trust_state: TrustState = TrustState.unset

    @property
    def id(self) -> str:
        """The device id.

        Same as the device_id attribute.
        """
        return self.device_id

    @property
    def ed25519(self) -> str:
        """The ed25519 fingerprint key of the device."""
        return self.keys["ed25519"]

    @ed25519.setter
    def ed25519(self, new_value):
        self.keys["ed25519"] = new_value

    @property
    def curve25519(self) -> str:
        """The curve25519 key of the device."""
        return self.keys["curve25519"]

    @curve25519.setter
    def curve25519(self, new_value):
        self.keys["curve25519"] = new_value

    def as_dict(self):
        """Convert the OlmDevice into a dictionary."""
        device = asdict(self)
        device["trust_state"] = self.trust_state.name

        return device

    @property
    def verified(self) -> bool:
        """Is the device verified."""
        return self.trust_state == TrustState.verified

    @property
    def ignored(self) -> bool:
        """Is the device ignored."""
        return self.trust_state == TrustState.ignored

    @property
    def blacklisted(self) -> bool:
        """Is the device blacklisted."""
        return self.trust_state == TrustState.blacklisted


class DeviceStore:
    """A store that holds olm devices in memory.

    The DeviceStore class implements the iter method, devices can be iterated
    over normally using:

    >>> for device in device_store:
    ...    print(device.user_id, device.device_id)

    To get only non-deleted devices of a user the active_user_devices method
    can be used:

    >>> for device in device_store.active_user_devices("@bob:example.org"):
    ...    print(device.user_id, device.device_id)

    """

    def __init__(self):
        self._entries: DefaultDict[str, Dict[str, OlmDevice]] = defaultdict(dict)

    def __iter__(self) -> Iterator[OlmDevice]:
        for user_devices in self._entries.values():
            yield from user_devices.values()

    def __getitem__(self, user_id: str) -> Dict[str, OlmDevice]:
        return self._entries[user_id]

    def items(self):
        """List of tuples in the form (user id, dict(device_id, OlmDevice)."""
        return self._entries.items()

    def values(self):
        """List of devices in the form of a dict(device_id, OlmDevice)."""
        return self._entries.values()

    def active_user_devices(self, user_id: str) -> Iterator[OlmDevice]:
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

    def device_from_sender_key(
        self, user_id: str, sender_key: str
    ) -> Optional[OlmDevice]:
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
    def users(self) -> KeysView[str]:
        """Get the list of users that the device store knows about."""
        return self._entries.keys()

    def devices(self, user_id: str) -> KeysView[str]:
        return self._entries[user_id].keys()

    def add(self, device: OlmDevice) -> bool:
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
