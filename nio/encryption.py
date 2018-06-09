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

import json
import os
import sqlite3
import pprint
# pylint: disable=redefined-builtin
from builtins import str, bytes
from collections import defaultdict
from functools import wraps
from typing import *

from jsonschema import ValidationError, SchemaError
from logbook import Logger
from olm import (Account, InboundGroupSession, InboundSession, OlmAccountError,
                 OlmGroupSessionError, OlmMessage, OlmPreKeyMessage,
                 OlmSessionError, OutboundGroupSession, OutboundSession,
                 Session)

from .schemas import Schemas, validate_json
from .log import logger_group

logger = Logger('nio.encryption')
logger_group.add_logger(logger)

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


try:
    FileNotFoundError  # type: ignore
except NameError:  # pragma: no cover
    FileNotFoundError = IOError


class OlmTrustError(Exception):
    pass


class EncryptionError(Exception):
    pass


class DeviceStore(object):
    def __init__(self, filename):
        # type: (str) -> None
        self._entries = []  # type: List[StoreEntry]
        self._filename = filename  # type: str

        self._load(filename)

    def __iter__(self):
        for entry in self._entries:
            yield OlmDevice(
                entry.user_id,
                entry.device_id,
                {entry.key_type: entry.key}
            )

    def _load(self, filename):
        # type: (str) -> None
        try:
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    entry = StoreEntry.from_line(line)

                    if not entry:
                        continue

                    self._entries.append(entry)
        except FileNotFoundError:
            pass

    def _save_store(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            self = args[0]
            ret = f(*args, **kwargs)
            self._save()
            return ret

        return decorated

    def _save(self):
        # type: () -> None
        with open(self._filename, "w") as f:
            for entry in self._entries:
                line = entry.to_line()
                f.write(line)

    @_save_store
    def add(self, device):
        # type: (OlmDevice) -> None
        new_entries = StoreEntry.from_olmdevice(device)
        self._entries += new_entries

        # Remove duplicate entries
        self._entries = list(set(self._entries))

        self._save()

    @_save_store
    def remove(self, device):
        # type: (OlmDevice) -> int
        removed = 0
        entries = StoreEntry.from_olmdevice(device)

        for entry in entries:
            if entry in self._entries:
                self._entries.remove(entry)
                removed += 1

        self._save()

        return removed

    def check(self, device):
        # type: (OlmDevice) -> bool
        return device in self


class StoreEntry(object):
    def __init__(self, user_id, device_id, key_type, key):
        # type: (str, str, str, str) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.key_type = key_type
        self.key = key

    @classmethod
    def from_line(cls, line):
        # type: (str) -> Optional[StoreEntry]
        fields = line.split(' ')

        if len(fields) < 4:
            return None

        user_id, device_id, key_type, key = fields[:4]

        if key_type == "matrix-ed25519":
            return cls(user_id, device_id, "ed25519", key)
        else:
            return None

    @classmethod
    def from_olmdevice(cls, device_key):
        # type: (OlmDevice) -> List[StoreEntry]
        entries = []

        user_id = device_key.user_id
        device_id = device_key.device_id

        for key_type, key in device_key.keys.items():
            if key_type == "ed25519":
                entries.append(cls(user_id, device_id, "ed25519", key))

        return entries

    def to_line(self):
        # type: () -> str
        key_type = "matrix-{}".format(self.key_type)
        line = "{} {} {} {}\n".format(
            self.user_id,
            self.device_id,
            key_type,
            self.key
        )
        return line

    def __hash__(self):
        # type: () -> int
        return hash(str(self))

    def __str__(self):
        # type: () -> str
        key_type = "matrix-{}".format(self.key_type)
        line = "{} {} {} {}".format(
            self.user_id,
            self.device_id,
            key_type,
            self.key
        )
        return line

    def __eq__(self, value):
        # type: (object) -> bool
        if not isinstance(value, StoreEntry):
            return NotImplemented

        if (self.user_id == value.user_id
                and self.device_id == value.device_id
                and self.key_type == value.key_type
                and self.key == value.key):
            return True

        return False


class OlmDevice(object):
    def __init__(self, user_id, device_id, key_dict):
        # type: (str, str, Dict[str, str]) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.keys = key_dict

    def __str__(self):
        # type: () -> str
        line = "{} {} {}".format(
            self.user_id,
            self.device_id,
            pprint.pformat(self.keys)
        )
        return line

    def __eq__(self, value):
        # type: (object) -> bool
        if not isinstance(value, OlmDevice):
            return NotImplemented

        try:
            # We only care for the fingerprint key.
            if (self.user_id == value.user_id
                    and self.device_id == value.device_id
                    and self.keys["ed25519"] == value.keys["ed25519"]):
                return True
        except KeyError:
            pass

        return False


class OneTimeKey(object):
    def __init__(self, user_id, device_id, key, key_type):
        # type: (str, str, str, str) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.key = key
        self.key_type = key_type


class OlmSession(object):
    def __init__(self, user_id, device_id, session):
        self.user_id = user_id
        self.device_id = device_id
        self.session = session

    @property
    def id(self):
        return "{}:{}:{}".format(self.user_id, self.device_id, self.session.id)

    def __eq__(self, value):
        # type: (object) -> bool
        if not isinstance(value, OlmSession):
            return NotImplemented

        if (self.user_id == value.user_id
                and self.device_id == value.device_id
                and self.session.id == value.session.id):
            return True

        return False

    def encrypt(self, plaintext):
        return self.session.encrypt(plaintext)

    def decrypt(self, message):
        # type: (Union[OlmMessage, OlmPreKeyMessage]) -> str
        return self.session.decrypt(message)

    def matches(self, message):
        # type: (Union[OlmMessage, OlmPreKeyMessage]) -> bool
        return self.session.matches(message)


class SessionStore(object):
    def __init__(self):
        self._entries = defaultdict(lambda: defaultdict(list)) \
            # type: DefaultDict[str, DefaultDict[str, List[Session]]]

    def add(self, session):
        # type: (OlmSession) -> bool
        if session in self._entries[session.user_id][session.device_id]:
            return False

        self._entries[session.user_id][session.device_id].append(session)
        self._entries[session.user_id][session.device_id].sort(
            key=lambda x: x.session.id
        )
        return True

    def __iter__(self):
        for user in self._entries.values():
            for device in user.values():
                for session in device:
                    yield session

    def check(self, session):
        # type: (OlmSession) -> bool
        if session in self._entries[session.user_id][session.device_id]:
            return True
        return False

    def remove(self, session):
        # type: (OlmSession) -> bool
        if session in self._entries[session.user_id][session.device_id]:
            self._entries[session.user_id][session.device_id].remove(session)
            return True

        return False

    def get(self, user_id, device_id):
        # type: (str, str) -> Optional[OlmSession]
        if self._entries[user_id][device_id]:
            return self._entries[user_id][device_id][0]

        return None

    def __getitem__(self, user_id):
        # type: (str) -> Dict[str, List[OlmSession]]
        return self._entries[user_id]

    def getall(self, user_id, device_id):
        # type: (str, str) -> List[OlmSession]
        return self._entries[user_id][device_id]


class Olm(object):
    def __init__(
        self,
        user_id,                     # type: str
        device_id,                   # type: str
        session_path,                # type: str
    ):
        # type: (...) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.session_path = session_path

        # List of group session ids that we shared with people
        self.shared_sessions = []  # type: List[str]

        # TODO the folowing dicts should probably be turned into classes with
        # nice interfaces for their operations
        # Dict containing devices of users that are members of encrypted rooms
        self.devices = {}  # type: Dict[str, List[OlmDevice]]

        self.session_store = SessionStore()  # type: SessionStore

        # Dict of inbound Megolm sessions
        # Dict[room_id, Dict[session_id, session]]
        self.inbound_group_sessions = defaultdict(dict) \
            # type: DefaultDict[str, Dict[str, InboundGroupSession]]

        # Dict of outbound Megolm sessions Dict[room_id]
        self.outbound_group_sessions = {} \
            # type: Dict[str, OutboundGroupSession]

        loaded = self.load()

        if not loaded:
            self.account = Account()
            self.save_account(True)

        # TODO we need a db for untrusted device as well as for seen devices.
        trust_file_path = "{}_{}.trusted_devices".format(user_id, device_id)
        self.trust_db = DeviceStore(os.path.join(
            session_path,
            trust_file_path
        ))

    def _create_inbound_session(self, sender, sender_key, message):
        logger.info("Creating Inbound session for {}".format(sender))
        # Let's create a new inbound session.
        session = InboundSession(self.account, message, sender_key)
        logger.info("Created Inbound session for {}".format(sender))
        # Remove the one time keys the session used so it can't be reused
        # anymore.
        self.account.remove_one_time_keys(session)
        # Save the account now that we removed the one time key.
        self.save_account()

        return session

    def verify_device(self, device):
        if device in self.trust_db:
            return False

        self.trust_db.add(device)
        return True

    def unverify_device(self, device):
        self.trust_db.remove(device)

    def create_session(self, user_id, device_id, one_time_key):
        # TODO the one time key needs to be verified before calling this

        id_key = None

        # Let's create a new outbound session
        logger.info("Creating Outbound for {} and device {}".format(
            user_id, device_id))

        # We need to find the device key for the wanted user and his device.
        for user, keys in self.devices.items():
            if user != user_id:
                continue

            for key in keys:
                if key.device_id == device_id:
                    # Found a device let's get the curve25519 key
                    id_key = key.keys["curve25519"]
                    break

        if not id_key:
            message = "Identity key for device {} not found".format(device_id)
            logger.error(message)
            raise EncryptionError(message)

        logger.info("Found identity key for device {}".format(device_id))
        # Create the session
        # TODO this can fail
        s = OutboundSession(self.account, id_key, one_time_key)
        # Save the account, add the session to the store and save it to the
        # database.
        self.save_account()
        session = OlmSession(user_id, device_id, s)

        self.session_store.add(session)
        self.save_session(session, new=True)
        logger.info("Created OutboundSession for device {}".format(device_id))

    def create_group_session(self, room_id, session_id, session_key):
        logger.info("Creating inbound group session for {}".format(room_id))
        session = InboundGroupSession(session_key)
        self.inbound_group_sessions[room_id][session_id] = session
        self.save_inbound_group_session(room_id, session)
        logger.info("Created inbound group session for {}".format(room_id))

    def create_outbound_group_session(self, room_id):
        logger.info("Creating outbound group session for {}".format(room_id))
        session = OutboundGroupSession()
        self.outbound_group_sessions[room_id] = session
        self.create_group_session(room_id, session.id, session.session_key)
        logger.info("Created outbound group session for {}".format(room_id))

    def get_missing_sessions(self, users):
        # type: (List[str]) -> Dict[str, Dict[str, str]]
        missing = {}

        for user in users:
            devices = []

            for key in self.devices[user]:
                # we don't need a session for our own device, skip it
                if key.device_id == self.device_id:
                    continue

                if not self.session_store.get(user, key.device_id):
                    logger.warn("Missing session for device {}".format(
                        key.device_id))
                    devices.append(key.device_id)

            if devices:
                missing[user] = {device: "signed_curve25519" for
                                 device in devices}

        return missing

    def _try_decrypt(
        self,
        sender,      # type: str
        message      # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> Optional[str]
        plaintext = None

        # Let's try to decrypt with each known session for the sender.
        # TODO do we wan't to try this with every session or just every session
        # for a specific device?
        for session_list in self.session_store[sender].values():
            for session in session_list:
                matches = False
                try:
                    if isinstance(message, OlmPreKeyMessage):
                        # It's a prekey message, check if the session matches
                        # if it doesn't no need to try to decrypt.
                        matches = session.matches(message)
                        if not matches:
                            continue

                    logger.info("Trying to decrypt olm message using existing "
                                "session for {} and device {}".format(
                                    sender,
                                    session.device_id
                                ))

                    plaintext = session.decrypt(message)
                    # TODO do we need to save the session in the database here?

                    logger.info("Succesfully decrypted olm message "
                                "using existing session")
                    return plaintext

                except OlmSessionError as e:
                    # Decryption failed using a matching session, we don't want
                    # to create a new session using this prekey message so
                    # raise an exception and log the error.
                    if matches:
                        logger.error("Found matching session yet decryption "
                                     "failed for sender {} and "
                                     "device {}".format(
                                         sender,
                                         session.device_id
                                     ))
                        raise EncryptionError("Decryption failed for matching "
                                              "session")

                    # Decryption failed, we'll try another session in the next
                    # iteration.
                    logger.info("Error decrypting olm message from {} "
                                "and device {}: {}".format(
                                    sender,
                                    session.device_id,
                                    str(e)
                                ))
                    pass

        return None

    def _verify_olm_payload(self, sender, payload):
        # type: (str, Dict[Any, Any]) -> bool
        # Verify that the sender in the payload matches the sender of the event
        if sender != payload["sender"]:
            return False

        # Verify that we're the recipient of the payload.
        if self.user_id != payload["recipient"]:
            return False

        # Verify that the recipient fingerprint key matches our own
        if (self.account.identity_keys["ed25519"] !=
                payload["recipient_keys"]["ed25519"]):
            return False

        # TODO check fingerprint key of the sender with the fingerprint key in
        # the keys payload key.

        return True

    def decrypt(
        self,
        sender,      # type: str
        sender_key,  # type: str
        message      # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> Optional[Dict[Any, Any]]

        s = None
        try:
            # First try to decrypt using an existing session.
            plaintext = self._try_decrypt(sender, message)
        except EncryptionError:
            # We found a matching session for a prekey message but decryption
            # failed, don't try to decrypt any further.
            return None

        # Decryption failed with every known session or no known sessions,
        # let's try to create a new session.
        if not plaintext:
            # New sessions can only be created if it's a prekey message, we
            # can't decrypt the message if it isn't one at this point in time
            # anymore, so return early
            if not isinstance(message, OlmPreKeyMessage):
                return None

            try:
                # Let's create a new session.
                s = self._create_inbound_session(sender, sender_key, message)
                # Now let's decrypt the message using the new session.
                plaintext = s.decrypt(message)
            except OlmSessionError as e:
                logger.error("Failed to create new session from prekey"
                             "message: {}".format(str(e)))
                return None

        # Mypy complains that the plaintext can still be empty here,
        # realistically this can't happen but let's make mypy happy
        if not plaintext:
            logger.error("Failed to decrypt Olm message: unknown error")
            return None

        # The plaintext should be valid json, let's parse it and verify it.
        try:
            parsed_payload = json.loads(plaintext, encoding='utf-8')
        except JSONDecodeError as e:
            # Failed parsing the payload, return early.
            logger.error("Failed to parse Olm message payload: {}".format(
                str(e)
            ))
            return None

        # Validate the payload, check that it contains all required keys as
        # well that the types of the values are the one we expect.
        # Note: The keys of the content object aren't checked here, the caller
        # should check the content depending on the type of the event
        try:
            validate_json(parsed_payload, Schemas.olm_event)
        except (ValidationError, SchemaError) as e:
            # Something is wrong with the payload log an error and return
            # early.
            logger.error("Error validating decrypted Olm event from {}"
                         ": {}".format(sender, str(e.message)))
            return None

        # Verify that the payload properties contain correct values:
        # sender/recipient/keys/recipient_keys
        if not self._verify_olm_payload(sender, parsed_payload):
            logger.error("Error verifying decrypted Olm event from {}".format(
                         sender))
            return None

        if s:
            # We created a new session, find out the device id for it and store
            # it in the session store as well as in the database.
            device_id = parsed_payload["sender_device"]
            session = OlmSession(sender, device_id, s)
            self.session_store.add(session)
            self.save_session(session, new=True)

        # Finaly return the parsed dict of the payload
        return parsed_payload

    def group_encrypt(
        self,
        room_id,         # type: str
        plaintext_dict,  # type: Dict[str, str]
        users            # type: List[str]
    ):
        # type: (...) -> Tuple[Dict[str, str], Optional[Dict[Any, Any]]]
        plaintext_dict["room_id"] = room_id
        to_device_dict = None  # type: Optional[Dict[str, Any]]

        if room_id not in self.outbound_group_sessions:
            self.create_outbound_group_session(room_id)

        if (self.outbound_group_sessions[room_id].id
                not in self.shared_sessions):
            to_device_dict = self.share_group_session(
                room_id,
                self.user_id,
                users
            )
            self.shared_sessions.append(
                self.outbound_group_sessions[room_id].id
            )

        session = self.outbound_group_sessions[room_id]

        ciphertext = session.encrypt(Olm._to_json(plaintext_dict))

        payload_dict = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "sender_key": self.account.identity_keys()["curve25519"],
            "ciphertext": ciphertext,
            "session_id": session.id,
            "device_id": self.device_id
        }

        return payload_dict, to_device_dict

    def group_decrypt(self, room_id, session_id, ciphertext):
        # type: (str, str, str) -> Optional[str]
        if session_id not in self.inbound_group_sessions[room_id]:
            return None

        session = self.inbound_group_sessions[room_id][session_id]
        try:
            plaintext = session.decrypt(ciphertext)
        except OlmGroupSessionError:
            return None

        return plaintext

    def share_group_session(self, room_id, users):
        # type: (str, str, List[str]) -> Dict[str, Any]
        group_session = self.outbound_group_sessions[room_id]

        key_content = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "room_id": room_id,
            "session_id": group_session.id,
            "session_key": group_session.session_key,
            "chain_index": group_session.message_index
        }

        payload_dict = {
            "type": "m.room_key",
            "content": key_content,
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {
                "ed25519": self.account.identity_keys()["ed25519"]
            }
        }

        to_device_dict = {
            "messages": {}
        }  # type: Dict[str, Any]

        for user in users:
            if user not in self.devices:
                continue

            for key in self.devices[user]:
                if key.device_id == self.device_id:
                    continue

                session = self.session_store.get(user, key.device_id)

                if not session:
                    continue

                if key not in self.trust_db:
                    raise OlmTrustError

                device_payload_dict = payload_dict.copy()
                device_payload_dict["recipient"] = user
                device_payload_dict["recipient_keys"] = {
                    "ed25519": key.keys["ed25519"]
                }

                olm_message = session.encrypt(
                    Olm._to_json(device_payload_dict)
                )

                olm_dict = {
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "sender_key": self.account.identity_keys()["curve25519"],
                    "ciphertext": {
                        key.keys["curve25519"]: {
                            "type": (0 if isinstance(
                                olm_message,
                                OlmPreKeyMessage
                            ) else 1),
                            "body": olm_message.ciphertext
                        }
                    }
                }

                if user not in to_device_dict["messages"]:
                    to_device_dict["messages"][user] = {}

                to_device_dict["messages"][user][key.device_id] = olm_dict

        return to_device_dict

    def load(self):
        # type: () -> bool

        db_file = "{}_{}.db".format(self.user_id, self.device_id)
        db_path = os.path.join(self.session_path, db_file)

        self.database = sqlite3.connect(db_path)
        new = Olm._check_db_tables(self.database)

        if new:
            return False

        cursor = self.database.cursor()

        cursor.execute(
            "select pickle from olmaccount where user = ?",
            (self.user_id,)
        )
        row = cursor.fetchone()
        account_pickle = row[0]

        cursor.execute("select user, device_id, pickle from olmsessions")
        db_sessions = cursor.fetchall()

        cursor.execute("select room_id, pickle from inbound_group_sessions")
        db_inbound_group_sessions = cursor.fetchall()

        cursor.close()

        try:
            try:
                account_pickle = bytes(account_pickle, "utf-8")
            except TypeError:
                pass

            self.account = Account.from_pickle(account_pickle)

            for db_session in db_sessions:
                session_pickle = db_session[2]
                try:
                    session_pickle = bytes(session_pickle, "utf-8")
                except TypeError:
                    pass

                s = Session.from_pickle(session_pickle)
                session = OlmSession(db_session[0], db_session[1], s)
                self.session_store.add(session)

            for db_session in db_inbound_group_sessions:
                session_pickle = db_session[1]
                try:
                    session_pickle = bytes(session_pickle, "utf-8")
                except TypeError:
                    pass

                s = InboundGroupSession.from_pickle(session_pickle)
                self.inbound_group_sessions[db_session[0]][s.id] = s

        except (OlmAccountError, OlmSessionError) as error:
            raise EncryptionError(error)

        return True

    def save(self):
        self.save_account()

        for session in self.session_store:
            self.save_session(session)

    def save_session(self, session, new=False):
        cursor = self.database.cursor()
        if new:
            cursor.execute("insert into olmsessions values(?,?,?,?)", (
                session.user_id,
                session.device_id,
                session.session.id,
                session.session.pickle()
            ))
        else:
            cursor.execute("update olmsessions set pickle=? where user = ? "
                           "and device_id = ? and session_id = ?", (
                               session.session.pickle(),
                               session.user_id,
                               session.device_id,
                               session.session.id
                           ))

        self.database.commit()

        cursor.close()

    def save_inbound_group_session(self, room_id, session):
        cursor = self.database.cursor()

        cursor.execute("insert into inbound_group_sessions values(?,?,?)",
                       (room_id, session.id, session.pickle()))

        self.database.commit()

        cursor.close()

    def save_account(self, new=False):
        cursor = self.database.cursor()

        if new:
            cursor.execute("insert into olmaccount values (?,?)",
                           (self.user_id, self.account.pickle()))
        else:
            cursor.execute("update olmaccount set pickle=? where user = ?",
                           (self.account.pickle(), self.user_id))

        self.database.commit()
        cursor.close()

    @staticmethod
    def _check_db_tables(database):
        # type: (sqlite3.Connection) -> bool
        new = False
        cursor = database.cursor()
        cursor.execute("""select name from sqlite_master where type='table'
                          and name='olmaccount'""")
        if not cursor.fetchone():
            cursor.execute("create table olmaccount (user text, pickle text)")
            database.commit()
            new = True

        cursor.execute("""select name from sqlite_master where type='table'
                          and name='olmsessions'""")
        if not cursor.fetchone():
            cursor.execute("""create table olmsessions (user text,
                              device_id text, session_id text, pickle text)""")
            database.commit()
            new = True

        cursor.execute("""select name from sqlite_master where type='table'
                          and name='inbound_group_sessions'""")
        if not cursor.fetchone():
            cursor.execute("""create table inbound_group_sessions
                              (room_id text, session_id text, pickle text)""")
            database.commit()
            new = True

        cursor.close()
        return new

    def sign_json(self, json_dict):
        # type: (Dict[Any, Any]) -> str
        signature = self.account.sign(self._to_json(json_dict))
        return signature

    @staticmethod
    def _to_json(json_dict):
        # type: (Dict[Any, Any]) -> str
        return json.dumps(
            json_dict,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True
        )

    def mark_keys_as_published(self):
        self.account.mark_keys_as_published()
