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

import sqlite3
import os

from builtins import super
from logbook import Logger
from collections import defaultdict
from typing import List, Optional
from datetime import timedelta, datetime

import olm

from .log import logger_group
from .exceptions import EncryptionError

logger = Logger("nio.cryptostore")
logger_group.add_logger(logger)


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


class Session(olm.Session):
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

    @property
    def expired(self):
        return False


class InboundSession(olm.InboundSession, Session):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, message, identity_key=None):
        super().__init__(account, message, identity_key)
        self.creation_time = datetime.now()


class OutboundSession(olm.OutboundSession, Session):
    def __new__(cls, *args):
        return super().__new__(cls, *args)

    def __init__(self, account, identity_key, one_time_key):
        super().__init__(account, identity_key, one_time_key)
        self.creation_time = datetime.now()


class InboundGroupSession(olm.InboundGroupSession):
    def __init__(self, session_key, signing_key):
        # type: (str, str) -> None
        self.ed25519 = signing_key
        self.forwarding_chain = []  # type: List[str]
        super().__init__(session_key)

    def __new__(cls, *args):
        return super().__new__(cls)

    @classmethod
    def from_pickle(
        cls,
        pickle,                 # type: bytes
        signing_key,            # type: str
        passphrase='',          # type: str
        forwarding_chain=None   # type: List[str]
    ):
        # type: (...) -> InboundGroupSession
        session = super().from_pickle(pickle, passphrase)
        session.ed25519 = signing_key
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
        # type: (...) -> InboundGroupSession
        account = super().from_pickle(pickle, passphrase)
        account.shared = shared
        return account


class CryptoStore(object):
    """Manages persistent storage for an OlmDevice.
    Args:
        user_id (str): The user ID of the OlmDevice.
        device_id (str): Optional. The device ID of the OlmDevice. Will be
            retrieved using ``user_id`` if not present.
        db_name (str): Optional. The name of the database file to use. Will
            be created if necessary.
        db_path (str): Optional. The path where to store the database file.
            Defaults to the system default application data directory.
        app_name (str): Optional. The application name, which will be used
            to determine where the database is located. Ignored if db_path
            is supplied.
        pickle_key (str): Optional. A key to encrypt the database contents.
    """

    def __init__(
        self,
        user_id,
        device_id,
        session_path,
        db_name=None,
        pickle_key="DEFAULT_KEY",
    ):
        self.user_id = user_id
        self.device_id = device_id
        db_name = db_name or "{}_{}.db".format(user_id, device_id)
        self.db_filepath = os.path.join(session_path, db_name)

        self._conn = self.instanciate_connection()
        self.pickle_key = pickle_key
        self.create_tables_if_needed()

    def instanciate_connection(self):
        con = sqlite3.connect(
            self.db_filepath, detect_types=sqlite3.PARSE_DECLTYPES
        )
        con.row_factory = sqlite3.Row
        return con

    def create_tables_if_needed(self):
        """Ensures all the tables exist."""
        c = self._conn.cursor()
        c.executescript(
            """
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts(
    device_id TEXT NOT NULL UNIQUE,
    account BLOB, user_id TEXT PRIMARY KEY NOT NULL, shared INTEGER
);
CREATE TABLE IF NOT EXISTS olm_sessions(
    device_id TEXT, session_id TEXT PRIMARY KEY, curve_key TEXT, session BLOB,
    creation_time TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_inbound_sessions(
    device_id TEXT, session_id TEXT PRIMARY KEY, room_id TEXT, curve_key TEXT,
    ed_key TEXT, session BLOB,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS forwarded_chains(
    device_id TEXT, session_id TEXT, curve_key TEXT,
    PRIMARY KEY(device_id, session_id, curve_key),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_outbound_sessions(
    device_id TEXT, room_id TEXT, session BLOB, max_age_s FLOAT,
    max_messages INTEGER, creation_time TIMESTAMP, message_count INTEGER,
    PRIMARY KEY(device_id, room_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS megolm_outbound_devices(
    device_id TEXT, room_id TEXT, user_device_id TEXT,
    PRIMARY KEY(device_id, room_id, user_device_id),
    FOREIGN KEY(device_id, room_id) REFERENCES
    megolm_outbound_sessions(device_id, room_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS device_keys(
    device_id TEXT, user_id TEXT, user_device_id TEXT, ed_key TEXT,
    curve_key TEXT, deleted INTEGER,
    PRIMARY KEY(device_id, user_id, user_device_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS tracked_users(
    device_id TEXT, user_id TEXT,
    PRIMARY KEY(device_id, user_id),
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS sync_tokens(
    device_id TEXT PRIMARY KEY, token TEXT,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS outgoing_key_requests(
    device_id TEXT PRIMARY KEY, session_id TEXT,
    FOREIGN KEY(device_id) REFERENCES accounts(device_id) ON DELETE CASCADE
);
        """
        )
        c.close()
        self._conn.commit()

    def save_olm_account(self, account):
        """Saves an Olm account.
        Args:
            account (OlmAccount): The account object to save.
        """
        account_data = account.pickle(self.pickle_key)
        c = self._conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO accounts "
            "(device_id, account, user_id, shared) VALUES (?,?,?,?)",
            (self.device_id, account_data, self.user_id, int(account.shared)),
        )
        c.execute(
            "UPDATE accounts SET account=?, shared=? WHERE device_id=?",
            (account_data, int(account.shared), self.device_id),
        )
        c.close()
        self._conn.commit()

    def replace_olm_account(self, account):
        """Replace an Olm account.
        Instead of updating it as done with :meth:`save_olm_account`,
        this saves the new account and discards all data associated with the
        previous one.
        Args:
            account (OlmAccount): The account object to save.
        """
        account_data = account.pickle(self.pickle_key)
        c = self._conn.cursor()
        c.execute(
            "REPLACE INTO accounts (device_id, account, user_id, shared) "
            "VALUES (?,?,?,?)",
            (self.device_id, account_data, self.user_id, int(account.shared)),
        )
        c.close()
        self._conn.commit()

    def get_olm_account(self):
        """Gets the Olm account.
        Returns:
            ``OlmAccount`` object, or ``None`` if it wasn't found for the
            current device_id.
        Raises:
            ``ValueError`` if ``device_id`` was ``None`` and couldn't be
            retrieved.
        """
        c = self._conn.cursor()
        if self.device_id:
            c.execute(
                "SELECT account, device_id, shared FROM accounts WHERE "
                "user_id=? AND device_id=?",
                (self.user_id, self.device_id),
            )
        else:
            c.execute(
                "SELECT account, device_id, shared FROM accounts "
                "WHERE user_id=?",
                (self.user_id,),
            )
        row = c.fetchone()
        if not row and not self.device_id:
            raise ValueError("Failed to retrieve device_id.")
        try:
            self.device_id = row["device_id"]
            account_data = row["account"]
            shared = bool(row["shared"])
            # sqlite gives us unicode in Python2, we want bytes
            account_data = bytes(account_data)
        except TypeError:
            return None
        finally:
            c.close()
        return OlmAccount.from_pickle(account_data, self.pickle_key, shared)

    def remove_olm_account(self):
        """Removes the Olm account.
        NOTE: Doing so will remove any saved information associated with the
        account (keys, sessions...)
        """
        c = self._conn.cursor()
        c.execute("DELETE FROM accounts WHERE user_id=?", (self.user_id,))
        c.close()

    def save_olm_session(self, curve_key, session):
        self.save_olm_sessions({curve_key: [session]})

    def save_olm_sessions(self, sessions):
        """Saves Olm sessions.
        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a
                list of ``olm.Session`` objects.
        """
        c = self._conn.cursor()
        rows = [
            (self.device_id, s.id, key, s.pickle(self.pickle_key),
                s.creation_time)
            for key in sessions
            for s in sessions[key]
        ]
        c.executemany("REPLACE INTO olm_sessions VALUES (?,?,?,?,?)", rows)
        c.close()
        self._conn.commit()

    def load_olm_sessions(self, sessions):
        """Loads all saved Olm sessions.
        Args:
            sessions (defaultdict(list)): A map from curve25519 keys to a
                list of ``olm.Session`` objects, which will be populated.
        """
        c = self._conn.cursor()
        rows = c.execute(
            ("SELECT curve_key, session , creation_time FROM olm_sessions "
                "WHERE device_id=?"),
            (self.device_id,),
        )
        for row in rows:
            session = Session.from_pickle(
                bytes(row["session"]), row["creation_time"], self.pickle_key
            )
            sessions[row["curve_key"]].append(session)
        c.close()

    def get_olm_sessions(self, curve_key, sessions_dict=None):
        """Get the Olm sessions corresponding to a device.
        Args:
            curve_key (str): The curve25519 key of the device.
            sessions_dict (defaultdict(list)): Optional. A map from curve25519
                keys to a list of ``olm.Session`` objects, to which the session
                list will be added.
        Returns:
            A list of ``olm.Session`` objects, or ``None`` if none were found.
        NOTE:
            When overriding this, be careful to append the retrieved sessions
            to the list of sessions already present and not to overwrite its
            reference.
        """
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT session, creation_time FROM olm_sessions "
            "WHERE device_id=? AND curve_key=?",
            (self.device_id, curve_key),
        )
        sessions = [
            olm.Session.from_pickle(
                bytes(row["session"]),
                row["creation_time"],
                self.pickle_key
            )
            for row in rows
        ]
        if sessions_dict is not None:
            sessions_dict[curve_key].extend(sessions)
        c.close()
        # For consistency with other get_ methods, do not return an empty list
        return sessions or None

    def save_inbound_session(self, room_id, curve_key, session):
        """Saves a Megolm inbound session.
        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session (InboundGroupSession): The session to save.
        """
        c = self._conn.cursor()
        c.execute(
            "REPLACE INTO megolm_inbound_sessions VALUES (?,?,?,?,?,?)",
            (
                self.device_id,
                session.id,
                room_id,
                curve_key,
                session.ed25519,
                session.pickle(self.pickle_key),
            ),
        )
        rows = [
            (self.device_id, session.id, curve_key)
            for curve_key in session.forwarding_chain
        ]
        c.executemany(
            "INSERT OR IGNORE INTO forwarded_chains VALUES(?,?,?)", rows
        )
        c.close()
        self._conn.commit()

    def load_inbound_sessions(self, sessions):
        """Loads all saved inbound Megolm sessions.
        Args:
            sessions (defaultdict(defaultdict(dict))): An object which will get
                populated with the sessions. The format is
                ``{<room_id>: {<curve25519_key>: {<session_id>:
                <InboundGroupSession>}}}``.
        """
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT * FROM megolm_inbound_sessions WHERE device_id=?",
            (self.device_id,),
        )
        for row in rows:
            session = InboundGroupSession.from_pickle(
                bytes(row["session"]), row["ed_key"], self.pickle_key
            )
            sessions[row["room_id"]][row["curve_key"]][session.id] = session
            self._load_forwarding_chain(session)
        c.close()

    def get_inbound_session(
        self, room_id, curve_key, session_id, sessions=None
    ):
        """Gets a saved inbound Megolm session.
        Args:
            room_id (str): The room corresponding to the session.
            curve_key (str): The curve25519 key of the device.
            session_id (str): The id of the session.
            sessions (dict): Optional. A map from session id to
                ``InboundGroupSession`` object, to which the session will be
                added.
        Returns:
            ``InboundGroupSession`` object, or ``None`` if the session was not
            found.
        """
        c = self._conn.cursor()
        c.execute(
            "SELECT session, ed_key FROM megolm_inbound_sessions WHERE "
            "device_id=? AND room_id=? AND curve_key=? AND session_id=?",
            (self.device_id, room_id, curve_key, session_id),
        )
        try:
            row = c.fetchone()
            session_data = bytes(row["session"])
        except TypeError:
            return None
        finally:
            c.close()
        session = InboundGroupSession.from_pickle(
            session_data, row["ed_key"], self.pickle_key
        )
        self._load_forwarding_chain(session)
        if sessions is not None:
            sessions[session.id] = session
        return session

    def _load_forwarding_chain(self, session):
        c = self._conn.cursor()
        c.execute(
            "SELECT curve_key FROM forwarded_chains WHERE device_id=? "
            "AND session_id=?",
            (self.device_id, session.id),
        )
        session.forwarding_chain = [row["curve_key"] for row in c]
        c.close()

    def save_device_keys(self, device_keys):
        """Saves device keys.
        Args:
            device_keys (defaultdict(dict)): The format is
                ``{<user_id>: {<device_id>: Device}}``.
        """
        c = self._conn.cursor()
        rows = []
        for user_id, devices_dict in device_keys.items():
            for device_id, device in devices_dict.items():
                rows.append(
                    (
                        self.device_id,
                        user_id,
                        device_id,
                        device.ed25519,
                        device.curve25519,
                        device.deleted
                    )
                )
        c.executemany(
            "REPLACE INTO device_keys VALUES (?,?,?,?,?,?)", rows
        )
        c.close()
        self._conn.commit()

    def load_device_keys(self, device_keys):
        """Loads all saved device keys.
        Args:
            device_keys (defaultdict(dict)): An object which will get populated
                with the keys. The format is
                ``{<user_id>: {<device_id>: Device}}``.
        """
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT * FROM device_keys WHERE device_id=?", (self.device_id,)
        )
        for row in rows:
            device_keys[row["user_id"]][
                row["user_device_id"]
            ] = self._device_from_row(row)
        c.close()

    def get_device_keys(self, user_devices, device_keys=None):
        """Gets the devices keys of the specified devices.
        Args:
            user_devices (dict): A map from user ids to a list of device ids.
                If no device ids are given for a user, all will be retrieved.
            device_keys (defaultdict(dict)): Optional. Will be updated with
                the retrieved keys. The format is ``{<user_id>: {<device_id>:
                Device}}``.
        Returns:
            A ``defaultdict(dict)`` containing the keys, the format is the same
            as the ``device_keys`` argument.
        """
        c = self._conn.cursor()
        rows = []
        for user_id in user_devices:
            if not user_devices[user_id]:
                c.execute(
                    "SELECT * FROM device_keys WHERE device_id=? "
                    "AND user_id=?",
                    (self.device_id, user_id),
                )
                rows.extend(c.fetchall())
            else:
                for device_id in user_devices[user_id]:
                    c.execute(
                        "SELECT * FROM device_keys WHERE device_id=? "
                        "AND user_id=? AND user_device_id=?",
                        (self.device_id, user_id, device_id),
                    )
                    rows.extend(c.fetchall())
        c.close()
        result = defaultdict(dict)
        for row in rows:
            result[row["user_id"]][
                row["user_device_id"]
            ] = self._device_from_row(row)

        if device_keys is not None and result:
            device_keys.update(result)
        return result

    def _device_from_row(self, row):
        return OlmDevice(
            row["user_id"],
            row["user_device_id"],
            ed25519_key=row["ed_key"],
            curve25519_key=row["curve_key"],
            deleted=bool(row["deleted"])
        )

    def save_tracked_users(self, user_ids):
        """Saves tracked users.
        Args:
            user_ids (iterable): The user ids to save.
        """
        c = self._conn.cursor()
        rows = [(self.device_id, user_id) for user_id in user_ids]
        c.executemany("INSERT OR IGNORE INTO tracked_users VALUES (?,?)", rows)
        c.close()
        self._conn.commit()

    def remove_tracked_users(self, user_ids):
        """Removes tracked users.
        Args:
            user_ids (iterable): The user ids to remove.
        """
        c = self._conn.cursor()
        rows = [(user_id,) for user_id in user_ids]
        c.executemany("DELETE FROM tracked_users WHERE user_id=?", rows)
        c.close()
        self._conn.commit()

    def load_tracked_users(self, tracked_users):
        """Loads all tracked users.
        Args:
            tracked_users (set): Will be populated with user ids.
        """
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT user_id FROM tracked_users WHERE device_id=?",
            (self.device_id,),
        )
        tracked_users.update(row["user_id"] for row in rows)
        c.close()
        return tracked_users

    def add_outgoing_key_request(self, session_id):
        """Saves a key request.
        Args:
            session_id (str): The requested session.
        """
        c = self._conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO outgoing_key_requests VALUES (?,?)",
            (self.device_id, session_id),
        )
        c.close()
        self._conn.commit()

    def remove_outgoing_key_request(self, session_id):
        """Removes a key request.
        Args:
            session_id (str): The requested session.
        """
        c = self._conn.cursor()
        c.execute(
            "DELETE FROM outgoing_key_requests WHERE device_id=? and "
            "session_id=?",
            (self.device_id, session_id),
        )
        c.close()

    def load_outgoing_key_requests(self, session_ids):
        """Load key requests.
        Args:
            session_ids (set): Will be populated with session IDs.
        """
        c = self._conn.cursor()
        c.execute(
            "SELECT session_id FROM outgoing_key_requests WHERE device_id=?",
            (self.device_id,),
        )
        for row in c:
            session_ids.add(row["session_id"])
        c.close()

    def close(self):
        self._conn.close()
