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


from builtins import super
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

import attr
import olm

from ..exceptions import EncryptionError
from ..event_builders import ToDeviceMessage, RoomKeyRequestMessage

if False:
    from ..responses import RoomKeyRequestResponse


class OlmAccount(olm.Account):
    def __init__(self):
        # type: () -> None
        self.shared = False
        super().__init__()

    def __new__(cls, *args):
        return super().__new__(cls)

    @classmethod
    def from_pickle(
        cls,
        pickle,                 # type: bytes
        passphrase='',          # type: str
        shared=False            # type: bool
    ):
        # type: (...) -> OlmAccount
        account = super().from_pickle(pickle, passphrase)
        account.shared = shared
        return account


class _SessionExpirationMixin(object):
    @property
    def expired(self):
        return False


class Session(olm.Session, _SessionExpirationMixin):
    def __init__(self):
        super().__init__()
        self.creation_time = datetime.now()
        self.use_time = datetime.now()

    def __new__(cls, *args):
        return super().__new__(cls, *args)

    @classmethod
    def from_pickle(cls, pickle, creation_time, passphrase="", use_time=None):
        # type: (str, datetime, str, Optional[datetime]) -> Session
        session = super().from_pickle(pickle, passphrase)
        session.creation_time = creation_time
        session.use_time = use_time or creation_time
        return session

    def decrypt(self, ciphertext):
        self.use_time = datetime.now()
        return super().decrypt(ciphertext)

    def encrypt(self, plaintext):
        self.use_time = datetime.now()
        return super().encrypt(plaintext)


class InboundSession(olm.InboundSession, _SessionExpirationMixin):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, message, identity_key=None):
        super().__init__(account, message, identity_key)
        self.creation_time = datetime.now()
        self.use_time = datetime.now()

    def decrypt(self, ciphertext):
        self.use_time = datetime.now()
        return super().decrypt(ciphertext)

    def encrypt(self, plaintext):
        self.use_time = datetime.now()
        return super().encrypt(plaintext)


class OutboundSession(olm.OutboundSession, _SessionExpirationMixin):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, identity_key, one_time_key):
        super().__init__(account, identity_key, one_time_key)
        self.creation_time = datetime.now()
        self.use_time = datetime.now()

    def decrypt(self, ciphertext):
        self.use_time = datetime.now()
        return super().decrypt(ciphertext)

    def encrypt(self, plaintext):
        self.use_time = datetime.now()
        return super().encrypt(plaintext)


class InboundGroupSession(olm.InboundGroupSession):
    def __init__(
        self,
        session_key,  # type: str
        signing_key,  # type: str
        sender_key,   # type: str
        room_id,      # type: str
        forwarding_chains=None  # type: Optional[List[str]]
    ):
        # type: (...) -> None
        self.ed25519 = signing_key
        self.sender_key = sender_key
        self.room_id = room_id
        self.forwarding_chain = forwarding_chains or []  # type: List[str]
        super().__init__(session_key)

    def __new__(cls, *args):
        return super().__new__(cls)

    @classmethod
    def from_pickle(
        cls,
        pickle,                 # type: bytes
        signing_key,            # type: str
        sender_key,             # type: str
        room_id,                # type: str
        passphrase='',          # type: str
        forwarding_chain=None   # type: List[str]
    ):
        # type: (...) -> InboundGroupSession
        session = super().from_pickle(pickle, passphrase)
        session.ed25519 = signing_key
        session.sender_key = sender_key
        session.room_id = room_id
        session.forwarding_chain = forwarding_chain or []
        return session

    @classmethod
    def import_session(
        cls,
        session_key,  # type: str
        signing_key,  # type: str
        sender_key,   # type: str
        room_id,      # type: str
        forwarding_chain=None  # type: Optional[List[str]]
    ):
        session = super().import_session(session_key)
        session.ed25519 = signing_key
        session.sender_key = sender_key
        session.room_id = room_id
        session.forwarding_chain = forwarding_chain or []
        return session


class OutboundGroupSession(olm.OutboundGroupSession):
    """Outbound group session aware of the users it is shared with.

    Also remembers the time it was created and the number of messages it has
    encrypted, in order to know if it needs to be rotated.

    Attributes:
        creation_time (datetime.datetime): Creation time of the session.
        message_count (int): Number of messages encrypted using the session.

    """

    def __init__(self):
        self.max_age = timedelta(days=7)
        self.max_messages = 100
        self.creation_time = datetime.now()
        self.message_count = 0
        self.users_shared_with = set()  # type: Set[Tuple[str, str]]
        self.users_ignored = set()      # type: Set[Tuple[str, str]]
        self.shared = False
        super().__init__()

    def __new__(cls, **kwargs):
        return super().__new__(cls)

    def mark_as_shared(self):
        self.shared = True

    @property
    def expired(self):
        return self.should_rotate()

    def should_rotate(self):
        """Wether the session should be rotated.
        Returns:
            True if it should, False if not.
        """
        if (self.message_count >= self.max_messages
                or datetime.now() - self.creation_time >= self.max_age):
            return True
        return False

    def encrypt(self, plaintext):
        if not self.shared:
            raise EncryptionError("Error, session is not shared")

        if self.expired:
            raise EncryptionError("Error, session is has expired")

        self.message_count += 1
        return super().encrypt(plaintext)


# TODO document the values better.
class TrustState(Enum):
    """The device trust state.

    An Enum holding differing values that a device trust state can be in.
    """

    unset = 0
    verified = 1
    blacklisted = 2
    ignored = 3


@attr.s
class OlmDevice(object):
    """Class holding info about users Olm devices.

    OlmDevices represent user devices with which we can communicate in an
    encrypted manner. To do so an OlmDevice needs to have its trust state set.
    The trust state can be set to one of "verified", "ignored", or
    "blacklisted".

    Note that the trust state should never be moddified directly on an
    OlmDevice, all the attributes here are read only.

    The trust state can be changed by pasing the OlmDevice to a nio Client or a
    MatrixStore class.

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

    user_id = attr.ib(type=str)
    device_id = attr.ib(type=str)
    keys = attr.ib(type=Dict[str, str])
    display_name = attr.ib(type=str, default="")
    deleted = attr.ib(type=bool, default=False)
    trust_state = attr.ib(type=TrustState, default=TrustState.unset)

    @property
    def id(self):
        """The device id.

        Same as the device_id attribute.
        """
        return self.device_id

    @property
    def ed25519(self):
        """The ed25519 fingerprint key of the device."""
        return self.keys["ed25519"]

    @ed25519.setter
    def ed25519(self, new_value):
        self.keys["ed25519"] = new_value

    @property
    def curve25519(self):
        """The curve25519 key of the device."""
        return self.keys["curve25519"]

    @curve25519.setter
    def curve25519(self, new_value):
        self.keys["curve25519"] = new_value

    def as_dict(self):
        """Convert the OlmDevice into a dictionary."""
        device = attr.asdict(self)
        device["trust_state"] = self.trust_state.name

        return device

    @property
    def verified(self):
        # type: () -> bool
        """Is the device verified."""
        return self.trust_state == TrustState.verified

    @property
    def ignored(self):
        # type: () -> bool
        """Is the device ignored."""
        return self.trust_state == TrustState.ignored

    @property
    def blacklisted(self):
        # type: () -> bool
        """Is the device blacklisted."""
        return self.trust_state == TrustState.blacklisted


@attr.s
class OutgoingKeyRequest(object):
    """Key request that we sent out."""

    request_id = attr.ib(type=str)
    session_id = attr.ib(type=str)
    room_id = attr.ib(type=str)
    algorithm = attr.ib(type=str)

    @classmethod
    def from_response(cls, response):
        # type: (RoomKeyRequestResponse) -> OutgoingKeyRequest
        """Create a key request object from a RoomKeyRequestResponse."""
        return cls(
            response.request_id,
            response.session_id,
            response.room_id,
            response.algorithm
        )

    @classmethod
    def from_message(cls, message):
        # type: (RoomKeyRequestMessage) -> OutgoingKeyRequest
        """Create a key request object from a RoomKeyRequestMessage."""
        return cls(
            message.request_id,
            message.session_id,
            message.room_id,
            message.algorithm,
        )

    @classmethod
    def from_database(cls, row):
        """Create a key request object from a database row."""
        return cls.from_response(row)

    def as_cancellation(self, user_id, requesting_device_id):
        """Turn the key request into a cancellation to-device message."""
        content = {
            "action": "request_cancellation",
            "request_id": self.request_id,
            "requesting_device_id": requesting_device_id,
        }

        return ToDeviceMessage(
            "m.room_key_request",
            user_id,
            "*",
            content
        )
