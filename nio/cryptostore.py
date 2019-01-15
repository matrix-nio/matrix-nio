# -*- coding: utf-8 -*-
# Copyright 2018 Zil0
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
import attr
import time

from builtins import bytes
from logbook import Logger
from typing import List, Optional, DefaultDict, Iterator, Dict
from datetime import datetime
from functools import wraps

from .log import logger_group
from .crypto import (
    OlmAccount,
    Session,
    InboundGroupSession,
    OlmDevice,
    SessionStore,
    GroupSessionStore,
    DeviceStore
)

from peewee import (
    SqliteDatabase,
    Model,
    TextField,
    BlobField,
    BooleanField,
    ForeignKeyField,
    CompositeKey,
    DoesNotExist
)


logger = Logger("nio.cryptostore")
logger_group.add_logger(logger)


class ByteField(BlobField):
    def python_value(self, value):
        if isinstance(value, bytes):
            return value

        return bytes(value, "utf-8")

    def db_value(self, value):
        if isinstance(value, bytearray):
            return bytes(value)

        return value


# Please don't remove this.
# This is a workaround for this bug: https://bugs.python.org/issue27400
class DateField(TextField):
    def python_value(self, value):
        format = "%Y-%m-%d %H:%M:%S.%f"
        try:
            return datetime.strptime(value, format)
        except TypeError:
            return datetime(*(time.strptime(value, format)[0:6]))

    def db_value(self, value):
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")


class Accounts(Model):
    account = ByteField()
    device_id = TextField(unique=True)
    shared = BooleanField()
    user_id = TextField(primary_key=True)

    class Meta:
        table_name = "accounts"


class DeviceKeys(Model):
    curve_key = TextField()
    deleted = BooleanField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=Accounts,
        on_delete="CASCADE"
    )
    ed_key = TextField()
    user_device_id = TextField()
    user_id = TextField()

    class Meta:
        table_name = "device_keys"
        indexes = (
            (("device", "user_id", "user_device_id"), True),
        )
        primary_key = CompositeKey("device", "user_device_id", "user_id")


class MegolmInboundSessions(Model):
    curve_key = TextField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=Accounts,
        on_delete="CASCADE"
    )
    ed_key = TextField()
    room_id = TextField()
    session = ByteField()
    session_id = TextField(primary_key=True)

    class Meta:
        table_name = "megolm_inbound_sessions"


class ForwardedChains(Model):
    curve_key = TextField()
    session = ForeignKeyField(
        MegolmInboundSessions,
        backref="forwarded_chains",
        on_delete="CASCADE"
    )


class OlmSessions(Model):
    creation_time = DateField()
    curve_key = TextField()
    device = ForeignKeyField(
        column_name="device_id",
        field="device_id",
        model=Accounts,
        on_delete="CASCADE"
    )
    session = ByteField()
    session_id = TextField(primary_key=True)

    class Meta:
        table_name = "olm_sessions"


class OutgoingKeyRequests(Model):
    session_id = TextField()
    device = ForeignKeyField(
        Accounts,
        on_delete="CASCADE",
        backref="key_requests",
    )


class SyncTokens(Model):
    token = TextField()
    device = ForeignKeyField(
        model=Accounts,
        primary_key=True,
        on_delete="CASCADE"
    )


class TrackedUsers(Model):
    user_id = TextField()
    device = ForeignKeyField(
        Accounts,
        on_delete="CASCADE"
    )


def use_database(fn):
    @wraps(fn)
    def inner(self, *args, **kwargs):
        with self.database.bind_ctx(self.models):
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
    ]

    user_id = attr.ib(type=str)
    device_id = attr.ib(type=str)
    store_path = attr.ib(type=str)
    pickle_key = attr.ib(type=str, default="DEFAULT_KEY")
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
    def load_account(self):
        # type: () -> Optional[OlmAccount]
        """Load the Olm account from the database.

        Returns:
            ``OlmAccount`` object, or ``None`` if it wasn't found for the
                current device_id.

        """
        try:
            account = Accounts.get(
                Accounts.user_id == self.user_id,
                Accounts.device_id == self.device_id
            )
        except DoesNotExist:
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
        ).on_conflict(
            conflict_target=(Accounts.device_id),
            preserve=(Accounts.user_id, Accounts.device_id),
            update={
                Accounts.account: account.pickle(self.pickle_key),
                Accounts.shared: account.shared
            }
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
                self.pickle_key,
                [chain.curve_key for chain in s.forwarded_chains]
            )
            store.add(session, s.room_id, s.curve_key)

        return store

    @use_database
    def save_inbound_group_session(self, room_id, curve_key, session):
        """Save the provided Megolm inbound group session to the database.

        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session (InboundGroupSession): The session to save.
        """
        MegolmInboundSessions.insert(
            curve_key=curve_key,
            device=self.device_id,
            ed_key=session.ed25519,
            room_id=room_id,
            session=session.pickle(self.pickle_key),
            session_id=session.id
        ).on_conflict(
            conflict_target=(MegolmInboundSessions.session_id),
            preserve=(
                MegolmInboundSessions.curve_key,
                MegolmInboundSessions.device,
                MegolmInboundSessions.ed_key,
                MegolmInboundSessions.room_id,
                MegolmInboundSessions.session_id,
            ),
            update={
                MegolmInboundSessions.session: session.pickle(self.pickle_key),
            }
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

    @use_database
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

        # TODO this needs to be batched
        DeviceKeys.replace_many(rows).execute()
