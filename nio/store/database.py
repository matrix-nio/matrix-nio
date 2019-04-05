# -*- coding: utf-8 -*-
# Copyright 2018 Zil0
# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from functools import wraps
from builtins import super
from typing import Optional

import attr

from peewee import (
    SqliteDatabase,
    DoesNotExist
)

from . import (
    Accounts,
    OlmSessions,
    MegolmInboundSessions,
    ForwardedChains,
    DeviceKeys,
    EncryptedRooms,
    OutgoingKeyRequests,
    Key,
    KeyStore
)

from ..crypto import (
    OlmAccount,
    Session,
    InboundGroupSession,
    OlmDevice,
    SessionStore,
    GroupSessionStore,
    DeviceStore,
    OutgoingKeyRequest
)


def use_database(fn):
    @wraps(fn)
    def inner(self, *args, **kwargs):
        with self.database.bind_ctx(self.models):
            return fn(self, *args, **kwargs)
    return inner


def use_database_atomic(fn):
    @wraps(fn)
    def inner(self, *args, **kwargs):
        with self.database.bind_ctx(self.models):
            with self.database.atomic():
                return fn(self, *args, **kwargs)
    return inner


@attr.s
class MatrixStore(object):
    """Storage class for matrix state."""

    models = [
        Accounts,
        OlmSessions,
        MegolmInboundSessions,
        ForwardedChains,
        DeviceKeys,
        EncryptedRooms,
        OutgoingKeyRequests,
    ]

    user_id = attr.ib(type=str)
    device_id = attr.ib(type=str)
    store_path = attr.ib(type=str)
    pickle_key = attr.ib(type=str, default="")
    database_name = attr.ib(type=str, default="")
    database_path = attr.ib(type=str, init=False)
    database = attr.ib(type=SqliteDatabase, init=False)

    def __attrs_post_init__(self):
        self.database_name = self.database_name or "{}_{}.db".format(
            self.user_id,
            self.device_id
        )
        self.database_path = os.path.join(self.store_path, self.database_name)
        self.database = SqliteDatabase(
            self.database_path,
            pragmas={
                "foreign_keys": 1,
                "secure_delete": 1,
            }
        )
        with self.database.bind_ctx(self.models):
            self.database.connect()
            self.database.create_tables(self.models)

    @use_database
    def _get_account(self):
        try:
            return Accounts.get(
                Accounts.user_id == self.user_id,
                Accounts.device_id == self.device_id
            )
        except DoesNotExist:
            return None

    def load_account(self):
        # type: () -> Optional[OlmAccount]
        """Load the Olm account from the database.

        Returns:
            ``OlmAccount`` object, or ``None`` if it wasn't found for the
                current device_id.

        """
        account = self._get_account()

        if not account:
            return None

        return OlmAccount.from_pickle(
            account.account,
            self.pickle_key,
            account.shared
        )

    @use_database
    def save_account(self, account):
        """Save the provided Olm account to the database.

        Args:
            account (OlmAccount): The olm account that will be pickled and
                saved in the database.
        """
        Accounts.insert(
            user_id=self.user_id,
            device_id=self.device_id,
            shared=account.shared,
            account=account.pickle(self.pickle_key)
        ).on_conflict_ignore().execute()

        Accounts.update(
            {
                Accounts.account: account.pickle(self.pickle_key),
                Accounts.shared: account.shared
            }
        ).where(
            (Accounts.user_id == self.user_id)
            & (Accounts.device_id == self.device_id)
        ).execute()

    @use_database
    def load_sessions(self):
        # type: () -> SessionStore
        """Load all Olm sessions from the database.

        Returns:
            ``SessionStore`` object, containing all the loaded sessions.

        """
        session_store = SessionStore()

        sessions = OlmSessions.select().join(Accounts).where(
            Accounts.device_id == self.device_id
        )

        for s in sessions:
            session = Session.from_pickle(
                s.session,
                s.creation_time,
                self.pickle_key
            )
            session_store.add(s.curve_key, session)

        return session_store

    @use_database
    def save_session(self, curve_key, session):
        """Save the provided Olm session to the database.

        Args:
            curve_key (str): The curve key that owns the Olm session.
            session (Session): The Olm session that will be pickled and
                saved in the database.
        """
        OlmSessions.replace(
            device=self.device_id,
            curve_key=curve_key,
            session=session.pickle(self.pickle_key),
            session_id=session.id,
            creation_time=session.creation_time
        ).execute()

    @use_database
    def load_inbound_group_sessions(self):
        # type: () -> GroupSessionStore
        """Load all Olm sessions from the database.

        Returns:
            ``GroupSessionStore`` object, containing all the loaded sessions.

        """
        store = GroupSessionStore()

        sessions = MegolmInboundSessions.select().join(Accounts).where(
            Accounts.device_id == self.device_id
        )

        for s in sessions:
            session = InboundGroupSession.from_pickle(
                s.session,
                s.ed_key,
                s.curve_key,
                s.room_id,
                self.pickle_key,
                [chain.curve_key for chain in s.forwarded_chains]
            )
            store.add(session)

        return store

    @use_database
    def save_inbound_group_session(self, session):
        """Save the provided Megolm inbound group session to the database.

        Args:
            session (InboundGroupSession): The session to save.
        """
        MegolmInboundSessions.insert(
            curve_key=session.sender_key,
            device=self.device_id,
            ed_key=session.ed25519,
            room_id=session.room_id,
            session=session.pickle(self.pickle_key),
            session_id=session.id
        ).on_conflict_ignore().execute()

        MegolmInboundSessions.update(
            {
                MegolmInboundSessions.session: session.pickle(self.pickle_key)
            }
        ).where(
            MegolmInboundSessions.session_id == session.id
        ).execute()

        # TODO, use replace many here
        for chain in session.forwarding_chain:
            ForwardedChains.replace(
                curve_key=chain,
                session=session.id
            ).execute()

    @use_database
    def load_device_keys(self):
        # type: () -> DeviceStore
        store = DeviceStore()
        device_keys = DeviceKeys.select().join(Accounts).where(
            Accounts.device_id == self.device_id
        )

        for d in device_keys:
            store.add(OlmDevice(
                d.user_id,
                d.user_device_id,
                d.ed_key,
                d.curve_key,
                d.deleted,
            ))

        return store

    @use_database_atomic
    def save_device_keys(self, device_keys):
        """Save the provided device keys to the database.

        Args:
            device_keys (Dict[str, Dict[str, OlmDevice]]): A dictionary
                containing a mapping from an user id to a dictionary containing
                a mapping of a device id to a OlmDevice.
        """
        rows = []

        for user_id, devices_dict in device_keys.items():
            for device_id, device in devices_dict.items():
                rows.append(
                    {
                        "curve_key": device.curve25519,
                        "deleted": device.deleted,
                        "device": self.device_id,
                        "ed_key": device.ed25519,
                        "user_device_id": device_id,
                        "user_id": user_id,
                    }
                )

        if not rows:
            return

        for idx in range(0, len(rows), 100):
            data = rows[idx:idx + 100]
            DeviceKeys.replace_many(data).execute()

    @use_database
    def load_encrypted_rooms(self):
        """Load the set of encrypted rooms for this account.

        Returns:
            ``Set`` containing room ids of encrypted rooms.

        """
        account = self._get_account()

        if not account:
            return set()

        return {room.room_id for room in account.encrypted_rooms}

    @use_database
    def load_outgoing_key_requests(self):
        """Load the set of outgoing key requests for this account.

        Returns:
            ``Set`` containing request ids of key requests.

        """
        account = self._get_account()

        if not account:
            return dict()

        return {request.request_id: OutgoingKeyRequest.from_response(request)
                for request in account.key_requests}

    @use_database
    def add_outgoing_key_request(self, key_request):
        # type: (OutgoingKeyRequest) -> None
        """Add a key request to the store."""
        account = self._get_account()
        assert account

        OutgoingKeyRequests.insert(
            request_id=key_request.request_id,
            session_id=key_request.session_id,
            room_id=key_request.room_id,
            algorithm=key_request.algorithm,
            device=account.device_id
        ).on_conflict_ignore().execute()

    @use_database_atomic
    def save_encrypted_rooms(self, rooms):
        """Save the set of room ids for this account."""
        account = self._get_account()

        assert account

        data = [(room_id, account) for room_id in rooms]

        for idx in range(0, len(data), 400):
            rows = data[idx:idx + 400]
            EncryptedRooms.insert_many(rows, fields=[
                EncryptedRooms.room_id,
                EncryptedRooms.account
            ]).on_conflict_ignore().execute()

    def blacklist_device(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError

    def unblacklist_device(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError

    def verify_device(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError

    def is_device_verified(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError

    def is_device_blacklisted(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError

    def unverify_device(self, device):
        # type: (OlmDevice) -> bool
        raise NotImplementedError


@attr.s
class DefaultStore(MatrixStore):
    trust_db = attr.ib(type=SqliteDatabase, init=False)
    blacklist_db = attr.ib(type=SqliteDatabase, init=False)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()

        trust_file_path = "{}_{}.trusted_devices".format(
            self.user_id,
            self.device_id
        )
        self.trust_db = KeyStore(
            os.path.join(self.store_path, trust_file_path)
        )

        blacklist_file_path = "{}_{}.blacklisted_devices".format(
            self.user_id,
            self.device_id
        )
        self.blacklist_db = KeyStore(
            os.path.join(self.store_path, blacklist_file_path)
        )

    def blacklist_device(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        self.trust_db.remove(key)
        return self.blacklist_db.add(key)

    def unblacklist_device(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        return self.blacklist_db.remove(key)

    def verify_device(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        self.blacklist_db.remove(key)
        return self.trust_db.add(key)

    def is_device_verified(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        return key in self.trust_db

    def is_device_blacklisted(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        return key in self.blacklist_db

    def unverify_device(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        return self.trust_db.remove(key)
