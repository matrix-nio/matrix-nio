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


from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, TypedDict, Union

import vodozemac
from unpaddedbase64 import decode_base64

from ..exceptions import EncryptionError


def get_pickle_key(passphrase: str = "") -> bytes:
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # TODO [vodozemac]: use proper pickle_keys, handle legacy ones?
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    return (passphrase + " "*32)[:32].encode()


class IdentityKeys(TypedDict):
    ed25519: str
    curve25519: str


class OlmAccount:
    def __init__(self, account: Optional[vodozemac.Account] = None) -> None:
        self._account = account or vodozemac.Account()
        self.shared = False

    # TODO [vodozemac]: add binding?
    @property
    def identity_keys(self) -> IdentityKeys:
        return {
            'ed25519': self._account.ed25519_key.to_base64(),
            'curve25519': self._account.curve25519_key.to_base64(),
        }

    @property
    def one_time_keys(self) -> Dict[str, Dict[str, str]]:
        return {
            # TODO [vodozemac]: keep old structure?
            'curve25519': {
                key_id: key.to_base64()
                for key_id, key in self._account.one_time_keys.items()
            }
        }

    @property
    def max_one_time_keys(self) -> int:
        return self._account.max_number_of_one_time_keys

    @classmethod
    def from_pickle(
        cls,
        pickle: bytes,
        passphrase: str = "",
        shared: bool = False,
    ) -> OlmAccount:
        try:
            pickle_key = get_pickle_key(passphrase)
            _account = vodozemac.Account.from_pickle(
                pickle.decode(), pickle_key)
        except vodozemac.PickleException:
            pickle_key = passphrase.encode()
            _account = vodozemac.Account.from_libolm_pickle(
                pickle.decode(), pickle_key)
        account = OlmAccount(account=_account)
        account.shared = shared
        return account

    def pickle(self, passphrase: str = "") -> bytes:
        return self._account.pickle(get_pickle_key(passphrase)).encode()

    def create_inbound_session(
        self,
        identity_key: str,
        message: Union[vodozemac.PreKeyMessage, vodozemac.AnyOlmMessage],
    ) -> vodozemac.Session:
        if isinstance(message, vodozemac.AnyOlmMessage):
            pre_key_message = message.to_pre_key()
            assert pre_key_message
            message = pre_key_message
        return self._account.create_inbound_session(
            vodozemac.Curve25519PublicKey.from_base64(identity_key),
            message,
        )

    def create_outbound_session(
        self,
        identity_key: str,
        one_time_key: str,
    ) -> vodozemac.Session:
        return self._account.create_outbound_session(
            vodozemac.Curve25519PublicKey.from_base64(identity_key),
            vodozemac.Curve25519PublicKey.from_base64(one_time_key),
        )

    def generate_one_time_keys(self, count: int) -> None:
        self._account.generate_one_time_keys(count)

    def remove_one_time_keys(self, session: Session) -> None:
        # TODO [vodozemac]: obsolete?
        pass

    def sign(self, message: str) -> str:
        return self._account.sign(message.encode()).to_base64()

    def mark_keys_as_published(self) -> None:
        self._account.mark_keys_as_published()


class _SessionExpirationMixin:
    @property
    def expired(self):
        return False

class Session(_SessionExpirationMixin):
    def __init__(self, session: Optional[vodozemac.Session] = None) -> None:
        self._session = session
        self.creation_time = datetime.now()
        self.use_time = datetime.now()

    @property
    def id(self) -> str:
        if not self._session:
            return ""
        return self._session.session_id

    @classmethod
    def from_pickle(
        cls,
        pickle: bytes,
        creation_time: datetime,
        passphrase: str = "",
        use_time: Optional[datetime] = None,
    ) -> Session:
        try:
            pickle_key = get_pickle_key(passphrase)
            _session = vodozemac.Session.from_pickle(
                pickle.decode(), pickle_key)
        except vodozemac.PickleException:
            pickle_key = passphrase.encode()
            _session = vodozemac.Session.from_libolm_pickle(
                pickle.decode(), pickle_key)
        session = Session(session=_session)
        session.creation_time = creation_time
        session.use_time = use_time or creation_time
        return session

    def pickle(self, passphrase: str = "") -> bytes:
        assert self._session
        return self._session.pickle(get_pickle_key(passphrase)).encode()

    def decrypt(
        self,
        message: Union[vodozemac.PreKeyMessage, vodozemac.AnyOlmMessage],
        unicode_errors="replace",
    ) -> str:
        assert self._session
        self.use_time = datetime.now()
        if isinstance(message, vodozemac.PreKeyMessage):
            message = message.to_any()
        return self._session.decrypt(message).decode(errors=unicode_errors)

    def encrypt(self, plaintext: str) -> vodozemac.AnyOlmMessage:
        assert self._session
        self.use_time = datetime.now()
        return self._session.encrypt(plaintext.encode())

    def matches(self, message: vodozemac.PreKeyMessage) -> bool:
        assert self._session
        return self._session.session_matches(message)


class InboundSession(Session):
    def __init__(
        self,
        account: OlmAccount,
        message: Union[vodozemac.PreKeyMessage, vodozemac.AnyOlmMessage],
        identity_key: str
    ) -> None:
        super().__init__()
        # TODO [vodozemac]: specify handling for first decryption
        # defer first decrytion to keep current api stable as vodozemac
        # returns the decrypted plaintext on creation of the inbound session
        def first_decrypt(
            msg: Union[vodozemac.PreKeyMessage, vodozemac.AnyOlmMessage]
        ) -> Tuple[vodozemac.Session, bytes]:
            return account.create_inbound_session(identity_key, msg)
        self.first_decrypt = first_decrypt

    def decrypt(
        self,
        message: Union[vodozemac.PreKeyMessage, vodozemac.AnyOlmMessage],
        unicode_errors="replace",
    ) -> str:
        if not self._session:
            session, plaintext = self.first_decrypt(message)
            self._session = session
            return plaintext.decode(errors=unicode_errors)
        return super().decrypt(message, unicode_errors)


class OutboundSession(Session):
    def __init__(
        self,
        account: OlmAccount,
        identity_key: str,
        one_time_key: str
    ) -> None:
        _session = account.create_outbound_session(identity_key, one_time_key)
        super().__init__(session=_session)


class InboundGroupSession:
    def __init__(
        self,
        session_key: str,
        signing_key: str,
        sender_key: str,
        room_id: str,
        forwarding_chain: Optional[List[str]] = None,
        session: Optional[vodozemac.InboundGroupSession] = None
    ) -> None:
        self._session = session or vodozemac.InboundGroupSession(
            vodozemac.SessionKey(session_key))
        self.ed25519 = signing_key
        self.sender_key = sender_key
        self.room_id = room_id
        self.forwarding_chain: List[str] = forwarding_chain or []

    @property
    def id(self) -> str:
        return self._session.session_id

    @property
    def first_known_index(self) -> int:
        return self._session.first_known_index

    @classmethod
    def import_session(
        cls,
        session_key: str,
        signing_key: str,
        sender_key: str,
        room_id: str,
        forwarding_chain: Optional[List[str]] = None,
    ) -> InboundGroupSession:
        _session = vodozemac.InboundGroupSession.import_session(
            vodozemac.ExportedSessionKey(session_key))
        session = InboundGroupSession(
            session_key='',
            signing_key=signing_key,
            sender_key=sender_key,
            room_id=room_id,
            forwarding_chain=forwarding_chain,
            session=_session,
        )
        return session

    def export_session(self, message_index: int) -> str:
        session = self._session.export_at(message_index)
        assert session
        return session.to_base64()

    @classmethod
    def from_pickle(
        cls,
        pickle: bytes,
        signing_key: str,
        sender_key: str,
        room_id: str,
        passphrase: str = "",
        forwarding_chain: Optional[List[str]] = None,
    ) -> InboundGroupSession:
        try:
            pickle_key = get_pickle_key(passphrase)
            _session = vodozemac.InboundGroupSession.from_pickle(
                pickle.decode(), pickle_key)
        except vodozemac.PickleException:
            pickle_key = passphrase.encode()
            _session = vodozemac.InboundGroupSession.from_libolm_pickle(
                pickle.decode, pickle_key)
        session = InboundGroupSession(
            session_key='',
            signing_key=signing_key,
            sender_key=sender_key,
            room_id=room_id,
            forwarding_chain=forwarding_chain,
            session=_session,
        )
        return session

    def pickle(self, passphrase: str = "") -> bytes:
        return self._session.pickle(get_pickle_key(passphrase)).encode()

    def decrypt(self, message: str, unicode_errors='replace') -> Tuple[str, int]:
        decrypted = self._session.decrypt(
            vodozemac.MegolmMessage.from_base64(message))
        return (decrypted.plaintext.decode(), decrypted.message_index)


class OutboundGroupSession:
    """Outbound group session aware of the users it is shared with.

    Also remembers the time it was created and the number of messages it has
    encrypted, in order to know if it needs to be rotated.

    Attributes:
        creation_time (datetime.datetime): Creation time of the session.
        message_count (int): Number of messages encrypted using the session.

    """

    def __init__(
        self,
        session: Optional[vodozemac.GroupSession] = None
    ) -> None:
        self._session = session or vodozemac.GroupSession()
        self.max_age = timedelta(days=7)
        self.max_messages = 100
        self.creation_time = datetime.now()
        self.message_count = 0
        self.users_shared_with: Set[Tuple[str, str]] = set()
        self.users_ignored: Set[Tuple[str, str]] = set()
        self.shared = False
        super().__init__()

    @property
    def id(self) -> str:
        return self._session.session_id

    @property
    def message_index(self) -> int:
        return self._session.message_index

    @property
    def session_key(self) -> str:
        return self._session.session_key.to_base64()

    @property
    def expired(self) -> str:
        return self.should_rotate()

    @classmethod
    def from_pickle(
        cls,
        pickle: bytes,
        passphrase: str = ""
    ) -> OutboundGroupSession:
        # TODO: bindings: no from_libolm_pickle()?
        pickle_key = get_pickle_key(passphrase)
        _session = vodozemac.GroupSession.from_pickle(
            pickle.decode(), pickle_key)
        return OutboundGroupSession(session=_session)

    def pickle(self, passphrase: str = "") -> bytes:
        return self._session.pickle(get_pickle_key(passphrase)).encode()

    def mark_as_shared(self):
        self.shared = True

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
        return self._session.encrypt(plaintext.encode()).to_base64()
