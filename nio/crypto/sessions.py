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
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Set, Tuple

import olm

from ..exceptions import EncryptionError


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
        pickle,  # type: bytes
        passphrase="",  # type: str
        shared=False,  # type: bool
    ):
        # type: (...) -> OlmAccount
        account = super().from_pickle(pickle, passphrase)
        account.shared = shared
        return account


class _SessionExpirationMixin:
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
        sender_key,  # type: str
        room_id,  # type: str
        forwarding_chains=None,  # type: Optional[List[str]]
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
        pickle,  # type: bytes
        signing_key,  # type: str
        sender_key,  # type: str
        room_id,  # type: str
        passphrase="",  # type: str
        forwarding_chain=None,  # type: List[str]
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
        sender_key,  # type: str
        room_id,  # type: str
        forwarding_chain=None,  # type: Optional[List[str]]
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
        self.users_ignored = set()  # type: Set[Tuple[str, str]]
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
        """Should the session be rotated?
        Returns:
            True if it should, False if not.
        """
        if (
            self.message_count >= self.max_messages
            or datetime.now() - self.creation_time >= self.max_age
        ):
            return True
        return False

    def encrypt(self, plaintext):
        if not self.shared:
            raise EncryptionError("Error, session is not shared")

        if self.expired:
            raise EncryptionError("Error, session is has expired")

        self.message_count += 1
        return super().encrypt(plaintext)
