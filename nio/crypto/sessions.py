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


import olm
import attr
from builtins import super, bytes
from datetime import datetime, timedelta
from typing import List, Optional, Set, Tuple
from future.moves.itertools import zip_longest


from ..exceptions import EncryptionError

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

    def __new__(cls, *args):
        return super().__new__(cls, *args)

    @classmethod
    def from_pickle(cls, pickle, creation_time, passphrase=""):
        # type: (str, datetime, str) -> Session
        session = super().from_pickle(pickle, passphrase)
        session.creation_time = creation_time
        return session


class InboundSession(olm.InboundSession, _SessionExpirationMixin):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, message, identity_key=None):
        super().__init__(account, message, identity_key)
        self.creation_time = datetime.now()


class OutboundSession(olm.OutboundSession, _SessionExpirationMixin):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, identity_key, one_time_key):
        super().__init__(account, identity_key, one_time_key)
        self.creation_time = datetime.now()


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


class OlmDevice(object):
    def __init__(
        self,
        user_id,         # type: str
        device_id,       # type: str
        ed25519_key,     # type: str
        curve25519_key,  # type: str
        deleted=False    # type: bool
    ):
        # type: (...) -> None
        self.user_id = user_id
        self.id = device_id
        self.ed25519 = ed25519_key
        self.curve25519 = curve25519_key
        self.deleted = deleted


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
        """Create an key request object from a RoomKeyRequestResponse."""
        return cls(
            response.request_id,
            response.session_id,
            response.room_id,
            response.algorithm
        )


class Sas(olm.Sas):
    emoji = ["🐶", "🐱", "🦁", "🐎", "🦄", "🐷", "🐘", "🐰", "🐼", "🐓",
             "🐧", "🐢", "🐟", "🐙", "🦋", "🌷", "🌳", "🌵", "🍄", "🌏",
             "🌙", "☁️ ", "🔥", "🍌", "🍎", "🍓", "🌽", "🍕", "🎂", "❤️ ",
             "😀", "🤖", "🎩", "👓", "🔧", "🎅", "👍", "☂️ ", "⌛", "⏰",
             "🎁", "💡", "📕", "✏️ ", "📎", "✂️ ", "🔒", "🔑", "🔨", "☎️ ",
             "🏁", "🚂", "🚲", "✈️ ", "🚀", "🏆", "⚽", "🎸", "🎺", "🔔",
             "⚓", "🎧", "📁", "📌"]

    def __init__(
        self,
        own_user,
        own_device,
        own_fp_key,
        transaction_id,
        other_user,
        other_device,
        short_auth_string
    ):
        self.own_user = own_user
        self.own_device = own_device
        self.own_fp_key = own_fp_key

        self.transaction_id = transaction_id
        self.other_user = other_user

        self.other_device = other_device
        self.short_auth_string = short_auth_string
        self.we_started_it = True
        super().__init__()

    @classmethod
    def from_key_verification_start(
        cls,
        own_user,
        own_device,
        own_fp_key,
        event
    ):
        obj = cls(
            own_user,
            own_device,
            own_fp_key,
            event.transaction_id,
            event.sender,
            event.from_device,
            event.short_authentication_string
        )
        obj.we_started_it = False
        return obj

    def receive_key(self, event):
        # TODO abort if the sender or transaciton id don't match
        self.set_their_pubkey(event.key)


    def _grouper(self, iterable, n, fillvalue=None):
        """Collect data into fixed-length chunks or blocks."""
        # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
        args = [iter(iterable)] * n
        return zip_longest(*args, fillvalue=fillvalue)

    def get_emoji(self):
        if self.we_started_it:
            info = ("MATRIX_KEY_VERIFICATION_SAS"
                    "{user_id}{device_id}{user_id}{transaction_id}".format(
                        user_id=self.other_user, device_id=self.other_device,
                        transaction_id=self.transaction_id))
        else:
            info = ("MATRIX_KEY_VERIFICATION_SAS"
                    "{first_user}{first_device}"
                    "{second_user}{second_device}{transaction_id}".format(
                        first_user=self.other_user,
                        first_device=self.other_device,
                        second_user=self.own_user,
                        second_device=self.own_device,
                        transaction_id=self.transaction_id))

        return self.generate_emoji(info)

    def generate_emoji(self, extra_info):
        generated_bytes = self.generate_bytes(extra_info, 6)
        number = "".join([format(x, "08b") for x in bytes(generated_bytes)])
        return [
            self.emoji[int(x, 2)] for x in
            map("".join, list(self._grouper(number[:42], 6)))
        ]

    def share_key(self):
        return {
            "transaction_id": self.transaction_id,
            "key": self.pubkey
        }

    def get_mac(self):
        key_id = "ed25519:{}".format(self.own_device)

        info = ("MATRIX_KEY_VERIFICATION_MAC"
                "{first_user}{first_device}"
                "{second_user}{second_device}{transaction_id}".format(
                    first_user=self.own_user,
                    first_device=self.own_device,
                    second_user=self.other_user,
                    second_device=self.other_device,
                    transaction_id=self.transaction_id))

        mac = {
            key_id: self.calculate_mac(self.own_fp_key, info + key_id)
        }

        return {
            "mac": mac,
            "keys": self.calculate_mac(key_id, info + "KEY_IDS"),
            "transaction_id": self.transaction_id,
        }
