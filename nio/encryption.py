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
import pprint
import sqlite3

# pylint: disable=redefined-builtin
from builtins import bytes, str, super
from collections import defaultdict, deque
from functools import wraps
from typing import (
    Any,
    DefaultDict,
    Deque,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

from jsonschema import SchemaError, ValidationError
from logbook import Logger
import olm
from olm import (
    Account,
    InboundSession,
    OlmAccountError,
    OlmGroupSessionError,
    OlmMessage,
    OlmPreKeyMessage,
    OlmSessionError,
    OutboundGroupSession,
    OutboundSession,
    Session,
)

from .log import logger_group
from .schemas import Schemas, validate_json
from .cryptostore import CryptoStore, InboundGroupSession, OlmDevice
from .api import Api

logger = Logger("nio.encryption")
logger_group.add_logger(logger)

try:
    from json.decoder import JSONDecodeError
except ImportError:  # pragma: no cover
    JSONDecodeError = ValueError  # type: ignore


try:
    FileNotFoundError  # type: ignore
except NameError:  # pragma: no cover
    FileNotFoundError = IOError


GroupStoreType = DefaultDict[
    str,
    DefaultDict[str, Dict[str, InboundGroupSession]]
]


class OlmTrustError(Exception):
    pass


class EncryptionError(Exception):
    pass


class VerificationError(Exception):
    pass


class Key(object):
    def __init__(self, user_id, device_id, key):
        # type: (str, str, str) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.key = key

    @classmethod
    def from_line(cls, line):
        # type: (str) -> Optional[Key]
        fields = line.split(" ")

        if len(fields) < 4:
            return None

        user_id, device_id, key_type, key = fields[:4]

        if key_type == "matrix-ed25519":
            return Ed25519Key(user_id, device_id, key)
        else:
            return None

    def to_line(self):
        # type: () -> str
        key_type = ""

        if isinstance(self, Ed25519Key):
            key_type = "matrix-ed25519"
        else:
            raise NotImplementedError(
                "Invalid key type {}".format(type(self.key))
            )

        line = "{} {} {} {}\n".format(
            self.user_id, self.device_id, key_type, str(self.key)
        )
        return line

    @classmethod
    def from_olmdevice(cls, device):
        # type: (OlmDevice) -> Ed25519Key
        user_id = device.user_id
        device_id = device.id
        return Ed25519Key(user_id, device_id, device.ed25519)


class Ed25519Key(Key):
    def __eq__(self, value):
        # type: (object) -> bool
        if not isinstance(value, Ed25519Key):
            return NotImplemented

        if (
            self.user_id == value.user_id
            and self.device_id == value.device_id
            and self.key == value.key
        ):
            return True

        return False


class DeviceStore(object):
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

    def add(self, device):
        # type: (OlmDevice) -> bool
        if device in self:
            return False

        self._entries[device.user_id][device.id] = device
        return True


class KeyStore(object):
    def __init__(self, filename):
        # type: (str) -> None
        self._entries = []  # type: List[Key]
        self._filename = filename  # type: str

        self._load(filename)

    def __iter__(self):
        # type: () -> Iterator[Key]
        for entry in self._entries:
            yield entry

    def __repr__(self):
        # type: () -> str
        return "FingerprintStore object, store file: {}".format(self._filename)

    def _load(self, filename):
        # type: (str) -> None
        try:
            with open(filename, "r") as f:
                for line in f:
                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    entry = Key.from_line(line)

                    if not entry:
                        continue

                    self._entries.append(entry)
        except FileNotFoundError:
            pass

    def get_key(self, user_id, device_id):
        # type: (str, str) -> Optional[Key]
        for entry in self._entries:
            if user_id == entry.user_id and device_id == entry.device_id:
                return entry

        return None

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
    def add(self, key):
        # type: (Key) -> bool
        existing_key = self.get_key(key.user_id, key.device_id)

        if existing_key:
            if (
                existing_key.user_id == key.user_id
                and existing_key.device_id == key.device_id
                and type(existing_key) is type(key)
            ):
                if existing_key.key != key.key:
                    message = (
                        "Error: adding existing device to trust store "
                        "with mismatching fingerprint {} {}".format(
                            key.key, existing_key.key
                        )
                    )
                    logger.error(message)
                    raise OlmTrustError(message)

        self._entries.append(key)
        self._save()
        return True

    @_save_store
    def remove(self, key):
        # type: (Key) -> bool
        if key in self._entries:
            self._entries.remove(key)
            self._save()
            return True

        return False

    def check(self, key):
        # type: (Key) -> bool
        return key in self._entries


class OlmSession(object):
    def __init__(self, user_id, device_id, identity_key, session):
        # type: (str, str, str, Session) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.identity_key = identity_key
        self.session = session

    @property
    def id(self):
        # type: () -> str
        return "{}:{}:{}".format(self.user_id, self.device_id, self.session.id)

    def __eq__(self, value):
        # type: (object) -> bool
        if not isinstance(value, OlmSession):
            return NotImplemented

        if (
            self.user_id == value.user_id
            and self.device_id == value.device_id
            and self.identity_key == value.identity_key
            and self.session.id == value.session.id
        ):
            return True

        return False

    def encrypt(self, plaintext):
        # type: (str) -> Union[OlmPreKeyMessage, OlmMessage]
        return self.session.encrypt(plaintext)

    def decrypt(self, message):
        # type: (Union[OlmMessage, OlmPreKeyMessage]) -> str
        return self.session.decrypt(message)

    def matches(self, message):
        # type: (Union[OlmMessage, OlmPreKeyMessage]) -> bool
        return self.session.matches(message)


class SessionStore(object):
    def __init__(self):
        # type: () -> None
        self._entries = defaultdict(list) \
            # type: DefaultDict[str, List[OlmSession]]

    def add(self, curve_key, session):
        # type: (str, OlmSession) -> bool
        if session in self._entries[curve_key]:
            return False

        self._entries[curve_key].append(session)
        self._entries[curve_key].sort(key=lambda x: x.id)
        return True

    def __iter__(self):
        # type: () -> Iterator[OlmSession]
        for session_list in self._entries.values():
            for session in session_list:
                yield session

    def get(self, curve_key):
        # type: (str) -> Optional[OlmSession]
        if self._entries[curve_key]:
            return self._entries[curve_key][0]

        return None

    def __getitem__(self, curve_key):
        # type: (str) -> List[OlmSession]
        return self._entries[curve_key]


class GroupSessionStore(object):
    def __init__(self):
        self._entries = defaultdict(lambda: defaultdict(dict))  \
                # type: GroupStoreType

    def __iter__(self):
        # type: () -> Iterator[InboundGroupSession]
        for room_sessions in self._entries.values():
            for sender_sessions in room_sessions.values():
                for session in sender_sessions.values():
                    yield session

    def add(self, session, room_id, sender_key):
        # type: (InboundGroupSession, str, str) -> bool
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


class Olm(object):
    def __init__(
        self,
        user_id,  # type: str
        device_id,  # type: str
        session_path,  # type: str
    ):
        # type: (...) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.session_path = session_path

        # List of group session ids that we shared with people
        self.shared_sessions = []  # type: List[str]

        # TODO the folowing dicts should probably be turned into classes with
        # nice interfaces for their operations

        # Dict[user_id, Dict[device_id, OlmDevice]]
        self.device_store = DeviceStore()
        # Dict[curve25519_key, List[OlmSession]]
        self.session_store = SessionStore()
        # Dict[RoomId, Dict[curve25519_key, Dict[session id, Session]]]
        self.inbound_group_store = GroupSessionStore()

        # Dict of outbound Megolm sessions Dict[room_id]
        self.outbound_group_sessions = {} \
            # type: Dict[str, OutboundGroupSession]

        self.store = CryptoStore(user_id, device_id, session_path)

        self.account = self.store.get_olm_account()

        if not self.account:
            self.account = Account()
            self.save_account()
        else:
            self.load()

        # TODO we need a db for untrusted device as well as for seen devices.
        trust_file_path = "{}_{}.trusted_devices".format(user_id, device_id)
        self.trust_db = KeyStore(os.path.join(session_path, trust_file_path))

    def _create_inbound_session(
        self,
        sender,  # type: str
        sender_key,  # type: str
        message,  # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> InboundSession
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
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        if key in self.trust_db:
            return False

        self.trust_db.add(key)
        return True

    def device_trusted(self, device):
        # type: (OlmDevice) -> bool
        key = Key.from_olmdevice(device)
        return key in self.trust_db

    def unverify_device(self, device):
        # type: (OlmDevice) -> None
        key = Key.from_olmdevice(device)
        self.trust_db.remove(key)

    def create_session(self, user_id, device_id, one_time_key):
        # type: (str, str, str) -> None
        # TODO the one time key needs to be verified before calling this

        curve_key = None

        # Let's create a new outbound session
        logger.info(
            "Creating Outbound for {} and device {}".format(user_id, device_id)
        )

        # We need to find the device key for the wanted user and his device.
        try:
            device = self.device_store[user_id][device_id]
            curve_key = device.curve25519
        except KeyError:
            message = "Identity key for device {} not found".format(device_id)
            logger.error(message)
            raise EncryptionError(message)

        logger.info("Found identity key for device {}".format(device_id))
        # Create the session
        # TODO this can fail
        session = OutboundSession(self.account, curve_key, one_time_key)
        # Save the account, add the session to the store and save it to the
        # database.
        self.save_account()

        self.session_store.add(curve_key, session)
        self.save_session(curve_key, session)
        logger.info("Created OutboundSession for device {}".format(device_id))

    def create_group_session(
        self, sender_key, sender_fp_key, room_id, session_id, session_key
    ):
        # type: (str, str, str, str, str) -> None
        logger.info(
            "Creating inbound group session for {} from {}".format(
                room_id, sender_key
            )
        )

        try:
            session = InboundGroupSession(session_key, sender_fp_key)
            if session.id != session_id:
                raise OlmSessionError(
                    "Mismatched session id while creating "
                    "inbound group session"
                )

        except OlmSessionError as e:
            logger.warn(e)
            return

        self.inbound_group_store.add(session, room_id, sender_key)
        self.save_inbound_group_session(room_id, sender_key, session)

    def create_outbound_group_session(self, room_id):
        # type: (str) -> None
        logger.info("Creating outbound group session for {}".format(room_id))
        session = OutboundGroupSession()
        self.outbound_group_sessions[room_id] = session

        id_key = self.account.identity_keys["curve25519"]
        fp_key = self.account.identity_keys["ed25519"]

        self.create_group_session(
            id_key, fp_key, room_id, session.id, session.session_key
        )
        logger.info("Created outbound group session for {}".format(room_id))

    def get_missing_sessions(self, users):
        # type: (List[str]) -> Dict[str, Dict[str, str]]
        missing = {}

        for user_id in users:
            devices = []

            for device in self.device_store[user_id].values():
                # we don't need a session for our own device, skip it
                if device.id == self.device_id:
                    continue

                if not self.session_store.get(device.curve25519):
                    logger.warn(
                        "Missing session for device {}".format(device.id)
                    )
                    devices.append(device.id)

            if devices:
                missing[user_id] = {
                    device: "signed_curve25519" for device in devices
                }

        return missing

    def _try_decrypt(
        self,
        sender,  # type: str
        sender_key,  # type: str
        message,  # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> Optional[str]
        plaintext = None

        # Let's try to decrypt with each known session for the sender.
        # for a specific device?
        for session in self.session_store[sender_key]:
            matches = False
            try:
                if isinstance(message, OlmPreKeyMessage):
                    # It's a prekey message, check if the session matches
                    # if it doesn't no need to try to decrypt.
                    matches = session.matches(message)
                    if not matches:
                        continue

                logger.info(
                    "Trying to decrypt olm message using existing "
                    "session for {} and device {}".format(
                        sender, session.device_id
                    )
                )

                plaintext = session.decrypt(message)
                # TODO do we need to save the session in the database here?

                logger.info(
                    "Succesfully decrypted olm message "
                    "using existing session"
                )
                return plaintext

            except OlmSessionError as e:
                # Decryption failed using a matching session, we don't want
                # to create a new session using this prekey message so
                # raise an exception and log the error.
                if matches:
                    logger.error(
                        "Found matching session yet decryption "
                        "failed for sender {} and "
                        "device {}".format(sender, session.device_id)
                    )
                    raise EncryptionError(
                        "Decryption failed for matching " "session"
                    )

                # Decryption failed, we'll try another session in the next
                # iteration.
                logger.info(
                    "Error decrypting olm message from {} "
                    "and device {}: {}".format(
                        sender, session.device_id, str(e)
                    )
                )
                pass

        return None

    def _verify_olm_payload(self, sender, payload):
        # type: (str, Dict[Any, Any]) -> bool
        # Verify that the sender in the payload matches the sender of the event
        if sender != payload["sender"]:
            raise VerificationError("Missmatched sender in Olm payload")

        # Verify that we're the recipient of the payload.
        if self.user_id != payload["recipient"]:
            raise VerificationError("Missmatched recipient in Olm " "payload")

        # Verify that the recipient fingerprint key matches our own
        if (
            self.account.identity_keys["ed25519"]
            != payload["recipient_keys"]["ed25519"]
        ):
            raise VerificationError(
                "Missmatched recipient key in " "Olm payload"
            )

        return True

    def _handle_olm_event(self, sender, sender_key, payload):
        # type: (str, str, Dict[Any, Any]) -> None
        logger.info("Recieved Olm event of type: {}".format(payload["type"]))

        if payload["type"] != "m.room_key":
            logger.warn(
                "Received unsuported Olm event of type {}".format(
                    payload["type"]
                )
            )
            return

        try:
            validate_json(payload, Schemas.room_key_event)
        except (ValidationError, SchemaError) as e:
            logger.error(
                "Error m.room_key event event from {}"
                ": {}".format(sender, str(e.message))
            )
            return None

        content = payload["content"]

        if content["algorithm"] != "m.megolm.v1.aes-sha2":
            logger.error(
                "Error: unsuported room key of type {}".format(
                    payload["algorithm"]
                )
            )
            return

        room_id = content["room_id"]

        logger.info(
            "Recieved new group session key for room {} "
            "from {}".format(room_id, sender)
        )

        self.create_group_session(
            sender_key,
            payload["keys"]["ed25519"],
            content["room_id"],
            content["session_id"],
            content["session_key"],
        )

        return

    def decrypt(
        self,
        sender,  # type: str
        sender_key,  # type: str
        message,  # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> None

        s = None
        try:
            # First try to decrypt using an existing session.
            plaintext = self._try_decrypt(sender, sender_key, message)
        except EncryptionError:
            # We found a matching session for a prekey message but decryption
            # failed, don't try to decrypt any further.
            return

        # Decryption failed with every known session or no known sessions,
        # let's try to create a new session.
        if not plaintext:
            # New sessions can only be created if it's a prekey message, we
            # can't decrypt the message if it isn't one at this point in time
            # anymore, so return early
            if not isinstance(message, OlmPreKeyMessage):
                return

            try:
                # Let's create a new session.
                s = self._create_inbound_session(sender, sender_key, message)
                # Now let's decrypt the message using the new session.
                plaintext = s.decrypt(message)
            except OlmSessionError as e:
                logger.error(
                    "Failed to create new session from prekey"
                    "message: {}".format(str(e))
                )
                return

        # Mypy complains that the plaintext can still be empty here,
        # realistically this can't happen but let's make mypy happy
        if not plaintext:
            logger.error("Failed to decrypt Olm message: unknown error")
            return

        # The plaintext should be valid json, let's parse it and verify it.
        try:
            parsed_payload = json.loads(plaintext, encoding="utf-8")
        except JSONDecodeError as e:
            # Failed parsing the payload, return early.
            logger.error(
                "Failed to parse Olm message payload: {}".format(str(e))
            )
            return

        # Validate the payload, check that it contains all required keys as
        # well that the types of the values are the one we expect.
        # Note: The keys of the content object aren't checked here, the caller
        # should check the content depending on the type of the event
        try:
            validate_json(parsed_payload, Schemas.olm_event)
        except (ValidationError, SchemaError) as e:
            # Something is wrong with the payload log an error and return
            # early.
            logger.error(
                "Error validating decrypted Olm event from {}"
                ": {}".format(sender, str(e.message))
            )
            return

        # Verify that the payload properties contain correct values:
        # sender/recipient/keys/recipient_keys and check if the sender device
        # is alread verified by us
        try:
            self._verify_olm_payload(sender, parsed_payload)

        except VerificationError as e:
            # We found a missmatched property don't process the event any
            # further
            logger.error(e)
            return

        else:
            # Verification succeded, handle the event
            self._handle_olm_event(sender, sender_key, parsed_payload)

        finally:
            if s:
                # We created a new session, find out the device id for it and
                # store it in the session store as well as in the database.
                self.session_store.add(sender_key, s)
                self.save_session(sender_key, s)

    def group_encrypt(
        self,
        room_id,  # type: str
        plaintext_dict,  # type: Dict[str, str]
    ):
        # type: (...) -> Dict[str, str]
        if room_id not in self.outbound_group_sessions:
            raise EncryptionError("Missing outbound session for room")

        session = self.outbound_group_sessions[room_id]

        plaintext_dict["room_id"] = room_id
        ciphertext = session.encrypt(Api.to_json(plaintext_dict))

        payload_dict = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "sender_key": self.account.identity_keys["curve25519"],
            "ciphertext": ciphertext,
            "session_id": session.id,
            "device_id": self.device_id,
        }

        return payload_dict

    def group_decrypt(self, room_id, sender_key, session_id, ciphertext):
        # type: (str, str, str, str) -> Optional[str]
        session = self.inbound_group_store.get(room_id, sender_key, session_id)

        if not session:
            logger.warn(
                "No session found with session id {} for "
                "room {}".format(session_id, room_id)
            )
            return None

        try:
            plaintext, message_index = session.decrypt(ciphertext)
            # TODO check that this isn't a replay attack.
            # TODO return the verification status of the message
            return plaintext
        except OlmGroupSessionError:
            return None

    def share_group_session(self, room_id, users):
        # type: (str, List[str]) -> Dict[str, Any]
        group_session = self.outbound_group_sessions[room_id]

        key_content = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "room_id": room_id,
            "session_id": group_session.id,
            "session_key": group_session.session_key,
            "chain_index": group_session.message_index,
        }

        payload_dict = {
            "type": "m.room_key",
            "content": key_content,
            "sender": self.user_id,
            "sender_device": self.device_id,
            "keys": {"ed25519": self.account.identity_keys["ed25519"]},
        }

        to_device_dict = {"messages": {}}  # type: Dict[str, Any]

        for user_id in users:
            for device in self.device_store[user_id].values():
                # No need to share the session with our own device
                if device.id == self.device_id:
                    continue

                session = self.session_store.get(device.curve25519)

                if not session:
                    continue

                if not self.device_trusted(device):
                    raise OlmTrustError("Trying to share group session with "
                                        "untrusted device")

                device_payload_dict = payload_dict.copy()
                device_payload_dict["recipient"] = user_id
                device_payload_dict["recipient_keys"] = {
                    "ed25519": device.ed25519
                }

                olm_message = session.encrypt(
                    Api.to_json(device_payload_dict)
                )

                olm_dict = {
                    "algorithm": "m.olm.v1.curve25519-aes-sha2",
                    "sender_key": self.account.identity_keys["curve25519"],
                    "ciphertext": {
                        device.curve25519: {
                            "type": (
                                0
                                if isinstance(olm_message, OlmPreKeyMessage)
                                else 1
                            ),
                            "body": olm_message.ciphertext,
                        }
                    },
                }

                if user_id not in to_device_dict["messages"]:
                    to_device_dict["messages"][user_id] = {}

                to_device_dict["messages"][user_id][device.id] = olm_dict

        return to_device_dict

    def load(self):
        # type: () -> None
        self.store.load_olm_sessions(self.session_store)
        self.store.load_inbound_sessions(self.inbound_group_store)
        self.store.load_device_keys(self.device_store)

    def save(self):
        # type: () -> None
        self.save_account()

        # for session in self.session_store:
        #     self.save_session(session)

    def save_session(self, curve_key, session):
        # type: (str, OlmSession) -> None
        self.store.save_olm_session(curve_key, session)

    def save_inbound_group_session(self, room_id, sender_key, session):
        # type: (str, str, InboundGroupSession) -> None
        self.store.save_inbound_session(room_id, sender_key, session)

    def save_account(self):
        # type: () -> None
        self.store.save_olm_account(self.account)

    def sign_json(self, json_dict):
        # type: (Dict[Any, Any]) -> str
        signature = self.account.sign(Api.to_json(json_dict))
        return signature

    def mark_keys_as_published(self):
        # type: () -> None
        self.account.mark_keys_as_published()
