# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
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
# pylint: disable=redefined-builtin
from builtins import str
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple, Union

import olm
from jsonschema import SchemaError, ValidationError
from olm import (OlmGroupSessionError, OlmMessage, OlmPreKeyMessage,
                 OlmSessionError)

from . import (DeviceStore, GroupSessionStore, InboundGroupSession,
               InboundSession, OlmAccount, OlmDevice, OutboundGroupSession,
               OutboundSession, Session, SessionStore, logger)
from ..api import Api
from ..events import (BadEvent, BadEventType, EncryptedEvent, Event,
                      ForwardedRoomKeyEvent, KeyVerificationAccept,
                      KeyVerificationCancel, KeyVerificationEvent,
                      KeyVerificationKey, KeyVerificationMac,
                      KeyVerificationStart, MegolmEvent, OlmEvent,
                      RoomEncryptedEvent, RoomKeyEvent, UnknownBadEvent,
                      validate_or_badevent)
from ..exceptions import (EncryptionError, GroupEncryptionError,
                          LocalProtocolError, OlmTrustError, VerificationError)
from ..responses import (KeysClaimResponse, KeysQueryResponse,
                         KeysUploadResponse, RoomKeyRequestResponse)
from ..schemas import Schemas, validate_json
from ..store import MatrixStore
from .key_export import decrypt_and_read, encrypt_and_save
from .sas import Sas, ToDeviceMessage
from .sessions import OutgoingKeyRequest

try:
    from json.decoder import JSONDecodeError
except ImportError:  # pragma: no cover
    JSONDecodeError = ValueError  # type: ignore


DecryptedOlmT = Union[ForwardedRoomKeyEvent, BadEvent, UnknownBadEvent, None]


class Olm(object):
    _olm_algorithm = 'm.olm.v1.curve25519-aes-sha2'
    _megolm_algorithm = 'm.megolm.v1.aes-sha2'
    _algorithms = [_olm_algorithm, _megolm_algorithm]
    _maxToDeviceMessagesPerRequest = 20
    _max_sas_life = timedelta(minutes=20)

    def __init__(
        self,
        user_id,    # type: str
        device_id,  # type: str
        store,      # type: MatrixStore
    ):
        # type: (...) -> None
        self.user_id = user_id
        self.device_id = device_id
        self.uploaded_key_count = None  # type: Optional[int]
        self.users_for_key_query = set()   # type: Set[str]

        # List of group session ids that we shared with people
        self.shared_sessions = []  # type: List[str]

        # Dict[user_id, Dict[device_id, OlmDevice]]
        self.device_store = DeviceStore()
        # Dict[curve25519_key, List[Session]]
        self.session_store = SessionStore()
        # Dict[RoomId, Dict[curve25519_key, Dict[session id, Session]]]
        self.inbound_group_store = GroupSessionStore()

        # Dict of outbound Megolm sessions Dict[room_id]
        self.outbound_group_sessions = {} \
            # type: Dict[str, OutboundGroupSession]

        self.tracked_users = set()  # type: Set[str]
        self.outgoing_key_requests = dict()  \
            # type: Dict[str, OutgoingKeyRequest]

        self.key_verifications = dict()  # type: Dict[str, Sas]
        self.outgoing_to_device_messages = []  # type: List[ToDeviceMessage]

        self.store = store

        account = self.store.load_account()  # type: ignore

        if not account:
            logger.info("Creating new Olm account for {} on device {}".format(
                        self.user_id, self.device_id))
            account = OlmAccount()
            self.save_account(account)
        else:
            self.load()

        self.account = account  # type: OlmAccount

    def update_tracked_users(self, room):
        already_tracked = self.tracked_users
        room_users = set(room.users.keys())

        missing = room_users - already_tracked

        if missing:
            self.users_for_key_query.update(missing)

    def add_changed_users(self, users):
        # type: (Set[str]) -> None
        """Add users that have changed keys to the query set."""
        self.users_for_key_query.update(users)

    @property
    def should_query_keys(self):
        if self.users_for_key_query:
            return True
        return False

    @property
    def should_upload_keys(self):
        if not self.account.shared:
            return True

        if self.uploaded_key_count is None:
            return False

        max_keys = self.account.max_one_time_keys
        key_count = (max_keys // 2) - self.uploaded_key_count
        return key_count > 0

    def user_fully_verified(self, user_id):
        # type: (str) -> bool
        devices = self.device_store.active_user_devices(user_id)
        for device in devices:
            if (not self.is_device_verified(device)
                    and not self.is_device_blacklisted(device)):
                return False

        return True

    def share_keys(self):
        # type: () -> Dict[str, Any]
        def generate_one_time_keys(current_key_count):
            # type: (int) -> None
            max_keys = self.account.max_one_time_keys

            key_count = (max_keys // 2) - current_key_count

            if key_count <= 0:
                raise ValueError("Can't share any keys, too many keys already "
                                 "shared")

            self.account.generate_one_time_keys(key_count)

        def device_keys():
            device_keys = {
                "algorithms": self._algorithms,
                "device_id": self.device_id,
                "user_id": self.user_id,
                "keys": {
                    "curve25519:" + self.device_id:
                        self.account.identity_keys["curve25519"],
                    "ed25519:" + self.device_id:
                        self.account.identity_keys["ed25519"]
                }
            }

            signature = self.sign_json(device_keys)

            device_keys["signatures"] = {
                self.user_id: {
                    "ed25519:" + self.device_id: signature
                }
            }
            return device_keys

        def one_time_keys():
            one_time_key_dict = {}

            keys = self.account.one_time_keys["curve25519"]

            for key_id, key in keys.items():
                key_dict = {"key": key}
                signature = self.sign_json(key_dict)

                one_time_key_dict["signed_curve25519:" + key_id] = {
                    "key": key_dict.pop("key"),
                    "signatures": {
                        self.user_id: {
                            "ed25519:" + self.device_id: signature
                        }
                    }
                }

            return one_time_key_dict

        content = {}  # type: Dict[Any, Any]

        # We're sharing our account for the first time, upload the identity
        # keys and one-time keys as well.
        if not self.account.shared:
            content["device_keys"] = device_keys()
            generate_one_time_keys(0)
            content["one_time_keys"] = one_time_keys()

        # Just upload one-time keys.
        else:
            if self.uploaded_key_count is None:
                raise EncryptionError("The uploaded key count is not known")

            generate_one_time_keys(self.uploaded_key_count)
            content["one_time_keys"] = one_time_keys()

        return content

    def _handle_key_claiming(self, response):
        keys = response.one_time_keys

        for user_id, user_devices in keys.items():
            for device_id, one_time_key in user_devices.items():
                # We need to find the device curve key for the wanted
                # user and his device.
                try:
                    device = self.device_store[user_id][device_id]
                except KeyError:
                    logger.warn("Curve key for user {} and device {} not "
                                "found, failed to start Olm session".format(
                                    user_id,
                                    device_id))
                    continue

                logger.info("Found curve key for user {} and device {}".format(
                    user_id,
                    device_id))

                key_object = next(iter(one_time_key.values()))

                verified = self.verify_json(key_object,
                                            device.ed25519,
                                            user_id,
                                            device_id)
                if verified:
                    logger.info("Succesfully verified signature for one-time "
                                "key of device {} of user {}.".format(
                                    device_id, user_id))
                    logger.info("Creating Outbound Session for device {} of "
                                "user {}".format(device_id, user_id))
                    self.create_session(key_object["key"], device.curve25519)
                else:
                    logger.warn("Signature verification for one-time key of "
                                "device {} of user {} failed, could not start "
                                "Olm session.".format(device_id, user_id))

    # This function is copyrighted under the Apache 2.0 license Zil0
    def _handle_key_query(self, response):
        # type: (KeysQueryResponse) -> None
        changed = defaultdict(dict)  \
            # type: DefaultDict[str, Dict[str, OlmDevice]]

        for user_id, device_dict in response.device_keys.items():
            try:
                self.users_for_key_query.remove(user_id)
            except KeyError:
                pass

            self.tracked_users.add(user_id)

            for device_id, payload in device_dict.items():
                if device_id == self.device_id:
                    continue

                if (payload['user_id'] != user_id
                        or payload['device_id'] != device_id):
                    logger.warn(
                        "Mismatch in keys payload of device %s "
                        "(%s) of user %s (%s).",
                        payload['device_id'],
                        device_id,
                        payload['user_id'],
                        user_id
                    )
                    continue

                try:
                    key_dict = payload["keys"]
                    signing_key = key_dict["ed25519:{}".format(device_id)]
                    curve_key = key_dict["curve25519:{}".format(device_id)]
                    if "unsigned" in payload:
                        display_name = payload["unsigned"].get(
                            "device_display_name",
                            ""
                        )
                    else:
                        display_name = ""
                except KeyError as e:
                    logger.warning(
                        "Invalid identity keys payload from device {} of"
                        " user {}: {}.".format(
                            device_id,
                            user_id,
                            e
                        ))
                    continue

                verified = self.verify_json(
                    payload,
                    signing_key,
                    user_id,
                    device_id
                )

                if not verified:
                    logger.warning(
                        "Signature verification failed for device {} of "
                        "user {}.".format(
                            device_id,
                            user_id))
                    continue

                user_devices = self.device_store[user_id]

                try:
                    device = user_devices[device_id]
                except KeyError:
                    logger.info("Adding new device to the device store for "
                                "user {} with device id {}".format(
                                    user_id,
                                    device_id
                                ))
                    self.device_store.add(OlmDevice(
                        user_id,
                        device_id,
                        {
                            "ed25519": signing_key,
                            "curve25519": curve_key
                        },
                        display_name=display_name
                    ))
                else:
                    if device.ed25519 != signing_key:
                        logger.warning("Ed25519 key has changed for device {} "
                                       "of user {}.".format(
                                           device_id,
                                           user_id
                                       ))
                        continue

                    if (device.curve25519 == curve_key
                            and device.display_name == display_name):
                        continue

                    device.curve25519 = curve_key
                    device.display_name = display_name

                    if device.curve25519 == curve_key:
                        logger.info("Updating curve key in the device store "
                                    "for user {} with device id {}".format(
                                        user_id, device_id))

                    elif device.display_name == display_name:
                        logger.info("Updating display name in the device "
                                    "store for user {} with device id "
                                    "{}".format(user_id, device_id))

                changed[user_id][device_id] = user_devices[device_id]

            current_devices = set(device_dict.keys())
            stored_devices = set(
                device.id for device in
                self.device_store.active_user_devices(user_id)
            )
            deleted_devices = stored_devices - current_devices

            for device_id in deleted_devices:
                device = self.device_store[user_id][device_id]
                device.deleted = True
                logger.info("Marking device {} of user {} as deleted".format(
                    user_id, device_id))
                changed[user_id][device_id] = device

        self.store.save_device_keys(changed)
        response.changed = changed

    def handle_response(self, response):
        if isinstance(response, KeysUploadResponse):
            self.account.shared = True
            self.uploaded_key_count = response.signed_curve25519_count
            self.mark_keys_as_published()
            self.save_account()

        elif isinstance(response, KeysQueryResponse):
            self._handle_key_query(response)

        elif isinstance(response, KeysClaimResponse):
            self._handle_key_claiming(response)

        elif isinstance(response, RoomKeyRequestResponse):
            key_request = OutgoingKeyRequest.from_response(response)
            self.outgoing_key_requests[response.request_id] = key_request
            self.store.add_outgoing_key_request(key_request)

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

    def blacklist_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.blacklist_device(device)

    def unblacklist_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.unblacklist_device(device)

    def verify_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.verify_device(device)

    def is_device_verified(self, device):
        # type: (OlmDevice) -> bool
        return self.store.is_device_verified(device)

    def is_device_blacklisted(self, device):
        # type: (OlmDevice) -> bool
        return self.store.is_device_blacklisted(device)

    def unverify_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.unverify_device(device)

    def ignore_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.ignore_device(device)

    def unignore_device(self, device):
        # type: (OlmDevice) -> bool
        return self.store.unignore_device(device)

    def is_device_ignored(self, device):
        # type: (OlmDevice) -> bool
        return self.store.is_device_ignored(device)

    def create_session(self, one_time_key, curve_key):
        # type: (str, str) -> None
        # TODO this can fail
        session = OutboundSession(self.account, curve_key, one_time_key)
        # Save the account, add the session to the store and save it to the
        # database.
        self.save_account()
        self.session_store.add(curve_key, session)
        self.save_session(curve_key, session)

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
            session = InboundGroupSession(
                session_key,
                sender_fp_key,
                sender_key,
                room_id
            )
            if session.id != session_id:
                raise OlmSessionError(
                    "Mismatched session id while creating "
                    "inbound group session"
                )

        except OlmSessionError as e:
            logger.warn(e)
            return

        self.inbound_group_store.add(session)
        self.save_inbound_group_session(session)

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
        # type: (List[str]) -> Dict[str, List[str]]
        missing = defaultdict(list)  # type: DefaultDict[str, List[str]]

        for user_id in users:
            for device in self.device_store.active_user_devices(user_id):
                # we don't need a session for our own device, skip it
                if device.id == self.device_id:
                    continue

                if not self.session_store.get(device.curve25519):
                    logger.warn(
                        "Missing session for device {}".format(device.id)
                    )
                    missing[user_id].append(device.id)

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
                    "session for {} and sender_key {}".format(
                        sender, sender_key
                    )
                )

                plaintext = session.decrypt(message)
                self.save_session(sender_key, session)

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
                        "sender key {}".format(sender, sender_key)
                    )
                    raise EncryptionError(
                        "Decryption failed for matching " "session"
                    )

                # Decryption failed, we'll try another session in the next
                # iteration.
                logger.info(
                    "Error decrypting olm message from {} "
                    "and sender key {}: {}".format(
                        sender, sender_key, str(e)
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

    def _handle_room_key_event(
        self,
        sender,      # type: str
        sender_key,  # type: str
        payload      # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[RoomKeyEvent, BadEventType, None]
        event = RoomKeyEvent.from_dict(payload, sender, sender_key)

        if isinstance(event, (BadEvent, UnknownBadEvent)):
            return event

        content = payload["content"]

        if event.algorithm != "m.megolm.v1.aes-sha2":
            logger.error(
                "Error: unsuported room key of type {}".format(
                    event.algorithm
                )
            )
            return event

        logger.info(
            "Recieved new group session key for room {} "
            "from {}".format(event.room_id, sender)
        )

        sender_fp_key = payload["keys"].get("ed25519", None)

        # TODO handle this better
        if not sender_fp_key:
            return None

        self.create_group_session(
            sender_key,
            sender_fp_key,
            content["room_id"],
            content["session_id"],
            content["session_key"],
        )

        return event

    # This function is copyrighted under the Apache 2.0 license Zil0
    def _handle_forwarded_room_key_event(
        self,
        sender,      # type: str
        sender_key,  # type: str
        payload      # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[ForwardedRoomKeyEvent, BadEventType, None]
        event = ForwardedRoomKeyEvent.from_dict(payload, sender, sender_key)

        if isinstance(event, (BadEvent, UnknownBadEvent)):
            return event

        if event.algorithm != "m.megolm.v1.aes-sha2":
            logger.error(
                "Error: unsuported forwarded room key of type {}".format(
                    event.algorithm
                )
            )
            return None

        if event.session_id not in self.outgoing_key_requests:
            logger.info(
                "Ignoring session key we have not requested from device {}.",
                sender_key
            )
            return None

        key_request = self.outgoing_key_requests[event.session_id]

        # TODO check that the algorithm, room_id and session id match

        content = payload["content"]

        session_sender_key = content["sender_key"]
        signing_key = content["sender_claimed_ed25519_key"]
        chain = content["forwarding_curve25519_key_chain"]
        chain.append(session_sender_key)

        session = Olm._import_group_session(
            content["session_key"],
            signing_key,
            session_sender_key,
            event.room_id,
            chain
        )

        if not session:
            return None

        if self.inbound_group_store.add(session):
            self.save_inbound_group_session(session)

        key_request = self.outgoing_key_requests.pop(key_request.request_id)
        self.store.remove_outgoing_key_request(key_request)
        self.outgoing_to_device_messages.append(
            key_request.as_cancellation(self.user_id, self.device_id)
        )

        return event

    def _handle_olm_event(
        self,
        sender,      # type: str
        sender_key,  # type: str
        payload      # type: Dict[Any, Any]
    ):
        # type: (...) -> DecryptedOlmT
        logger.info("Recieved Olm event of type: {}".format(payload["type"]))

        if payload["type"] == "m.room_key":
            event = self._handle_room_key_event(sender, sender_key, payload)
            return event  # type: ignore

        elif payload["type"] == "m.forwarded_room_key":
            return self._handle_forwarded_room_key_event(
                sender,
                sender_key,
                payload
            )

        else:
            logger.warn(
                "Received unsuported Olm event of type {}".format(
                    payload["type"]
                )
            )
            return None

    def decrypt_megolm_event(self, event):
        # type (MegolmEvent) -> Union[Event, BadEvent]
        if not event.room_id:
            raise EncryptionError("Event doens't contain a room id")

        verified = False

        session = self.inbound_group_store.get(
            event.room_id,
            event.sender_key,
            event.session_id
        )

        if not session:
            message = (
                "Error decrypting megolm event, no session found "
                "with session id {} for room {}".format(
                    event.session_id,
                    event.room_id
                )
            )
            logger.warn(message)
            raise EncryptionError(message)

        try:
            plaintext, message_index = session.decrypt(event.ciphertext)
        except OlmGroupSessionError as e:
            message = "Error decrypting megolm event: {}".format(str(e))
            logger.warn(message)
            raise EncryptionError(message)

        # TODO check the message index for replay attacks

        # If the message is from our own session mark it as verified
        if (event.sender == self.user_id
                and event.device_id == self.device_id
                and session.ed25519
                == self.account.identity_keys["ed25519"]
                and event.sender_key
                == self.account.identity_keys["curve25519"]):
            verified = True
        # Else check that the message is from a verified device
        else:
            try:
                device = self.device_store[event.sender][event.device_id]
            except KeyError:
                # We don't have the device keys for this device, add them
                # to our quey set so we fetch in the next key query.
                self.users_for_key_query.add(event.sender)
                pass
            else:
                # Do not mark events decrypted using a forwarded key as
                # verified
                if (self.is_device_verified(device)
                        and not session.forwarding_chain):
                    if (device.ed25519 != session.ed25519
                            or device.curve25519 != event.sender_key):
                        message = ("Device keys mismatch in event sent "
                                   "by device {}.".format(device.id))
                        logger.warn(message)
                        raise EncryptionError(message)

                    logger.info("Event {} succesfully verified".format(
                        event.event_id))
                    verified = True

        try:
            parsed_dict = json.loads(plaintext, encoding="utf-8") \
                # type: Dict[Any, Any]
        except JSONDecodeError as e:
            raise EncryptionError("Error parsing payload: {}".format(str(e)))

        bad = validate_or_badevent(
            parsed_dict,
            Schemas.room_megolm_decrypted
        )

        if bad:
            return bad

        parsed_dict["event_id"] = event.event_id
        parsed_dict["sender"] = event.sender
        parsed_dict["origin_server_ts"] = event.server_timestamp

        if event.transaction_id:
            parsed_dict["unsigned"] = {
                "transaction_id": event.transaction_id
            }

        new_event = EncryptedEvent.parse_event(parsed_dict)

        if isinstance(new_event, UnknownBadEvent):
            return new_event

        new_event.decrypted = True
        new_event.verified = verified
        new_event.sender_key = event.sender_key
        new_event.session_id = event.session_id

        return new_event

    def decrypt_event(
        self,
        event  # type: RoomEncryptedEvent
    ):
        # type: (...) -> Union[Event, BadEventType, RoomKeyEvent, None]
        logger.debug("Decrypting event of type {}".format(
            type(event).__name__
        ))
        if isinstance(event, OlmEvent):
            try:
                own_key = self.account.identity_keys["curve25519"]
                own_ciphertext = event.ciphertext[own_key]
            except KeyError:
                logger.warn("Olm event doesn't contain ciphertext for our key")
                return None

            if own_ciphertext["type"] == 0:
                message = OlmPreKeyMessage(own_ciphertext["body"])
            elif own_ciphertext["type"] == 1:
                message = OlmMessage(own_ciphertext["body"])
            else:
                logger.warn("Unsuported olm message type: {}".format(
                    own_ciphertext["type"]))
                return None

            return self.decrypt(event.sender, event.sender_key, message)

        elif isinstance(event, MegolmEvent):
            try:
                return self.decrypt_megolm_event(event)
            except EncryptionError:
                return None

        return None

    def decrypt(
        self,
        sender,  # type: str
        sender_key,  # type: str
        message,  # type: Union[OlmPreKeyMessage, OlmMessage]
    ):
        # type: (...) -> DecryptedOlmT

        try:
            # First try to decrypt using an existing session.
            plaintext = self._try_decrypt(sender, sender_key, message)
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
                # Store the new session
                self.session_store.add(sender_key, s)
                self.save_session(sender_key, s)
            except OlmSessionError as e:
                logger.error(
                    "Failed to create new session from prekey"
                    "message: {}".format(str(e))
                )
                return None

        # Mypy complains that the plaintext can still be empty here,
        # realistically this can't happen but let's make mypy happy
        if not plaintext:
            logger.error("Failed to decrypt Olm message: unknown error")
            return None

        # The plaintext should be valid json, let's parse it and verify it.
        try:
            parsed_payload = json.loads(plaintext, encoding="utf-8")
        except JSONDecodeError as e:
            # Failed parsing the payload, return early.
            logger.error(
                "Failed to parse Olm message payload: {}".format(str(e))
            )
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
            logger.error(
                "Error validating decrypted Olm event from {}"
                ": {}".format(sender, str(e.message))
            )
            return None

        # Verify that the payload properties contain correct values:
        # sender/recipient/keys/recipient_keys and check if the sender device
        # is alread verified by us
        try:
            self._verify_olm_payload(sender, parsed_payload)

        except VerificationError as e:
            # We found a missmatched property don't process the event any
            # further
            logger.error(e)
            return None

        else:
            # Verification succeded, handle the event
            return self._handle_olm_event(sender, sender_key, parsed_payload)

    def rotate_outbound_group_session(self, room_id):
        logger.info("Rotating outbound group session for room {}".format(
            room_id))
        self.create_outbound_group_session(room_id)

    def group_encrypt(
        self,
        room_id,  # type: str
        plaintext_dict,  # type: Dict[Any, Any]
    ):
        # type: (...) -> Dict[str, str]
        if room_id not in self.outbound_group_sessions:
            self.create_outbound_group_session(room_id)

        session = self.outbound_group_sessions[room_id]

        if session.expired:
            self.rotate_outbound_group_session(room_id)
            session = self.outbound_group_sessions[room_id]

        if not session.shared:
            raise GroupEncryptionError("Group session for room {} not "
                                       "shared.".format(room_id))

        plaintext_dict["room_id"] = room_id
        ciphertext = session.encrypt(Api.to_json(plaintext_dict))

        payload_dict = {
            "algorithm": self._megolm_algorithm,
            "sender_key": self.account.identity_keys["curve25519"],
            "ciphertext": ciphertext,
            "session_id": session.id,
            "device_id": self.device_id,
        }

        return payload_dict

    def share_group_session(
        self,
        room_id,  # type: str
        users,    # type: List[str]
        ignore_missing_sessions=False,   # type: bool
        ignore_unverified_devices=False  # type: bool
    ):
        # type: (...) -> Tuple[Set[Tuple[str, str]], Dict[str, Any]]
        logger.info("Sharing group session for room {}".format(room_id))
        if room_id not in self.outbound_group_sessions:
            self.create_outbound_group_session(room_id)

        group_session = self.outbound_group_sessions[room_id]

        if group_session.shared:
            raise LocalProtocolError("Group session already shared")

        key_content = {
            "algorithm": self._megolm_algorithm,
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

        already_shared_set = group_session.users_shared_with
        ignored_set = group_session.users_ignored

        user_map = []

        for user_id in users:
            for device in self.device_store.active_user_devices(user_id):
                # No need to share the session with our own device
                if device.id == self.device_id:
                    ignored_set.add((user_id, device.id))
                    continue

                if self.is_device_blacklisted(device):
                    ignored_set.add((user_id, device.id))
                    continue

                if ((user_id, device.id) in already_shared_set
                        or (user_id, device.id) in ignored_set):
                    continue

                session = self.session_store.get(device.curve25519)

                if not session:
                    if ignore_missing_sessions:
                        ignored_set.add((user_id, device.id))
                        continue
                    else:
                        raise EncryptionError("Missing Olm session for user {}"
                                              " and device {}".format(
                                                  user_id,
                                                  device.id))

                if not self.is_device_verified(device):
                    if self.is_device_ignored(device):
                        pass
                    elif ignore_unverified_devices:
                        self.ignore_device(device)
                    else:
                        raise OlmTrustError("Device {} for user {} is not "
                                            "verified or blacklisted.".format(
                                                device.id,
                                                device.user_id
                                            ))

                user_map.append((user_id, device, session))

                if len(user_map) >= self._maxToDeviceMessagesPerRequest:
                    break

            if len(user_map) >= self._maxToDeviceMessagesPerRequest:
                break

        sharing_with = set()

        for user_id, device, session in user_map:
            # No need to share the session with our own device
            device_payload_dict = payload_dict.copy()
            device_payload_dict["recipient"] = user_id
            device_payload_dict["recipient_keys"] = {
                "ed25519": device.ed25519
            }

            olm_message = session.encrypt(
                Api.to_json(device_payload_dict)
            )
            self.store.save_session(device.curve25519, session)

            olm_dict = {
                "algorithm": self._olm_algorithm,
                "sender_key": self.account.identity_keys["curve25519"],
                "ciphertext": {
                    device.curve25519: {
                        "type": olm_message.message_type,
                        "body": olm_message.ciphertext,
                    }
                },
            }

            sharing_with.add((user_id, device.id))

            if user_id not in to_device_dict["messages"]:
                to_device_dict["messages"][user_id] = {}

            to_device_dict["messages"][user_id][device.id] = olm_dict

        return sharing_with, to_device_dict

    def load(self):
        # type: () -> None
        self.session_store = self.store.load_sessions()
        self.inbound_group_store = self.store.load_inbound_group_sessions()
        self.device_store = self.store.load_device_keys()
        self.outgoing_key_requests = self.store.load_outgoing_key_requests()

    def save_session(self, curve_key, session):
        # type: (str, Session) -> None
        self.store.save_session(curve_key, session)

    def save_inbound_group_session(self, session):
        # type: (InboundGroupSession) -> None
        self.store.save_inbound_group_session(session)

    def save_account(self, account=None):
        # type: (Optional[OlmAccount]) -> None
        if account:
            self.store.save_account(account)
        else:
            self.store.save_account(self.account)
        logger.debug("Saving account")

    def sign_json(self, json_dict):
        # type: (Dict[Any, Any]) -> str
        signature = self.account.sign(Api.to_canonical_json(json_dict))
        return signature

    # This function is copyrighted under the Apache 2.0 license Zil0
    def verify_json(self, json, user_key, user_id, device_id):
        """Verifies a signed key object's signature.
        The object must have a 'signatures' key associated with an object of
        the form `user_id: {key_id: signature}`.
        Args:
            json (dict): The JSON object to verify.
            user_key (str): The public ed25519 key which was used to sign
                the object.
            user_id (str): The user who owns the device.
            device_id (str): The device who owns the key.
        Returns:
            True if the verification was successful, False if not.
        """
        try:
            signatures = json.pop('signatures')
        except (KeyError, ValueError):
            return False

        key_id = 'ed25519:{}'.format(device_id)
        try:
            signature_base64 = signatures[user_id][key_id]
        except KeyError:
            json['signatures'] = signatures
            return False

        unsigned = json.pop('unsigned', None)

        try:
            olm.ed25519_verify(
                user_key,
                Api.to_canonical_json(json),
                signature_base64
            )
            success = True
        except olm.utility.OlmVerifyError:
            success = False

        json['signatures'] = signatures
        if unsigned:
            json['unsigned'] = unsigned

        return success

    def mark_keys_as_published(self):
        # type: () -> None
        self.account.mark_keys_as_published()

    @staticmethod
    def export_keys_static(sessions, outfile, passphrase, count=10000):
        session_list = []

        for session in sessions:
            payload = {
                "algorithm": Olm._megolm_algorithm,
                "sender_key": session.sender_key,
                "sender_claimed_keys": {
                    "ed25519": session.ed25519
                },
                "forwarding_curve25519_key_chain": session.forwarding_chain,
                "room_id": session.room_id,
                "session_id": session.id,
                "session_key": session.export_session(
                    session.first_known_index
                )
            }
            session_list.append(payload)

        data = json.dumps(session_list).encode()
        encrypt_and_save(data, outfile, passphrase, count=count)

    # This function is copyrighted under the Apache 2.0 license Zil0
    def export_keys(self, outfile, passphrase, count=10000):
        """Export all the Megolm decryption keys of this device.

        The keys will be encrypted using the passphrase.
        NOTE:
            This does not save other information such as the private identity
            keys of the device.
        Args:
            outfile (str): The file to write the keys to.
            passphrase (str): The encryption passphrase.
            count (int): Optional. Round count for the underlying key
                derivation. It is not recommended to specify it unless
                absolutely sure of the consequences.
        """
        inbound_group_store = self.store.load_inbound_group_sessions()

        Olm.export_keys_static(inbound_group_store, outfile, passphrase, count)

        logger.info(
            "Succesfully exported encryption keys to {}".format(outfile)
        )

    @staticmethod
    def _import_group_session(
        session_key,
        sender_fp_key,
        sender_key,
        room_id,
        forwarding_chain
    ):
        try:
            return InboundGroupSession.import_session(
                session_key,
                sender_fp_key,
                sender_key,
                room_id,
                forwarding_chain,
            )
        except OlmSessionError as e:
            logger.warn("Error importing inbound group session: {}".format(e))
            return None

    @staticmethod
    def import_keys_static(infile, passphrase):
        # type: (str, str) -> List[InboundGroupSession]
        sessions = []

        try:
            data = decrypt_and_read(infile, passphrase)
        except ValueError as e:
            raise EncryptionError(e)

        try:
            session_list = json.loads(data)
        except JSONDecodeError as e:
            raise EncryptionError("Error parsing key file: {}".format(str(e)))

        try:
            validate_json(session_list, Schemas.megolm_key_import)
        except (ValidationError, SchemaError) as e:
            logger.warning(e)
            raise EncryptionError("Error parsing key file: {}".format(str(e)))

        for session_dict in session_list:
            if session_dict["algorithm"] != Olm._megolm_algorithm:
                logger.warning("Ignoring session with unsupported algorithm.")
                continue

            session = Olm._import_group_session(
                session_dict["session_key"],
                session_dict["sender_claimed_keys"]["ed25519"],
                session_dict["sender_key"],
                session_dict["room_id"],
                session_dict["forwarding_curve25519_key_chain"],
            )

            if not session:
                continue

            sessions.append(session)

        return sessions

    # This function is copyrighted under the Apache 2.0 license Zil0
    def import_keys(self, infile, passphrase):
        """Import Megolm decryption keys.

        The keys will be added to the current instance as well as written to
        database.

        Args:
            infile (str): The file containing the keys.
            passphrase (str): The decryption passphrase.
        """
        sessions = Olm.import_keys_static(infile, passphrase)

        for session in sessions:
            # This could be improved by writing everything to db at once at
            # the end
            if self.inbound_group_store.add(session):
                self.save_inbound_group_session(session)

        logger.info(
            "Successfully imported encryption keys from {}".format(infile)
        )

    def clear_verifications(self):
        """Remove canceled or done key verifications from our cache.

        Returns a list of events that need to be added to the to-device event
        stream of our caller.

        """
        acitve_sas = dict()
        events = []

        now = datetime.now()

        for transaction_id, sas in self.key_verifications.items():
            if sas.timed_out:
                message = sas.get_cancellation()
                self.outgoing_to_device_messages.append(message)
                cancel_event = {
                    "sender": self.user_id,
                    "content": message.content
                }
                events.append(KeyVerificationCancel.from_dict(cancel_event))
                continue
            elif sas.canceled or sas.verified:
                if now - sas.creation_time > self._max_sas_life:
                    continue
                acitve_sas[transaction_id] = sas
            else:
                acitve_sas[transaction_id] = sas

        self.key_verifications = acitve_sas

        return events

    def create_sas(self, olm_device):
        sas = Sas(
            self.user_id,
            self.device_id,
            self.account.identity_keys["ed25519"],
            olm_device
        )
        self.key_verifications[sas.transaction_id] = sas

        return sas.start_verification()

    def get_active_sas(self, user_id, device_id):
        # type: (str, str) -> Optional[Sas]
        """Find a non-canceled SAS verification object for the provided user.

        Args:
            user_id (str): The user for which we should find a SAS verification
                object.
            device_id (str): The device_id for which we should find the SAS
                verification object.

        Returns the object if it's found, otherwise None.
        """
        verifications = [
            x for x in self.key_verifications.values() if not x.canceled
        ]

        for sas in sorted(
            verifications,
            key=lambda x: x.creation_time,
            reverse=True
        ):
            device = sas.other_olm_device
            if device.user_id == user_id and device.id == device_id:
                return sas

        return None

    def handle_key_verification(self, event):
        # type: (KeyVerificationEvent) -> None
        """Receive key verification events."""
        if isinstance(event, KeyVerificationStart):
            logger.info("Received key verification start event from "
                        "{} {} {}".format(
                            event.sender,
                            event.from_device,
                            event.transaction_id
                        ))
            try:
                device = self.device_store[event.sender][event.from_device]
            except KeyError:
                logger.warn("Received key verification event from unknown "
                            "device: {} {}".format(
                                event.sender,
                                event.from_device
                            ))
                self.users_for_key_query.add(event.sender)
                return

            new_sas = Sas.from_key_verification_start(
                self.user_id,
                self.device_id,
                self.account.identity_keys["ed25519"],
                device,
                event
            )

            if new_sas.canceled:
                logger.warn("Received malformed key verification event from "
                            "{} {}".format(
                                event.sender,
                                event.from_device
                            ))
                message = new_sas.get_cancellation()
                self.outgoing_to_device_messages.append(message)

            else:
                old_sas = self.get_active_sas(event.sender, event.from_device)

                if old_sas:
                    logger.info("Found an active verification process for the "
                                "same user/device combination, "
                                "canceling the old one. "
                                "Old Sas: {} {} {}".format(
                                    event.sender,
                                    event.from_device,
                                    old_sas.transaction_id
                                ))
                    old_sas.cancel()
                    cancel_message = old_sas.get_cancellation()
                    self.outgoing_to_device_messages.append(cancel_message)

                logger.info("Sucesfully started key verification with "
                            "{} {} {}".format(
                                event.sender,
                                event.from_device,
                                new_sas.transaction_id
                            ))
                self.key_verifications[event.transaction_id] = new_sas

        else:
            sas = self.key_verifications.get(event.transaction_id, None)

            if not sas:
                logger.warn("Received key verification event with an unknown "
                            "transaction id from {}".format(event.sender))
                return

            if isinstance(event, KeyVerificationAccept):
                sas.receive_accept_event(event)

                if sas.canceled:
                    message = sas.get_cancellation()
                else:
                    logger.info("Received a key verification accept event "
                                "from {} {}, sharing keys {}".format(
                                    event.sender,
                                    sas.other_olm_device.id,
                                    sas.transaction_id))
                    message = sas.share_key()

                self.outgoing_to_device_messages.append(message)

            elif isinstance(event, KeyVerificationCancel):
                logger.info("Received a key verification cancellation "
                            "from {} {}. Canceling verification {}.".format(
                                event.sender,
                                sas.other_olm_device.id,
                                sas.transaction_id))
                sas = self.key_verifications.pop(event.transaction_id, None)

                if sas:
                    sas.cancel()

            elif isinstance(event, KeyVerificationKey):
                sas.receive_key_event(event)
                message = None

                if sas.canceled:
                    message = sas.get_cancellation()
                else:
                    logger.info("Received a key verification pubkey "
                                "from {} {} {}.".format(
                                    event.sender,
                                    sas.other_olm_device.id,
                                    sas.transaction_id))

                if not sas.we_started_it and not sas.canceled:
                    message = sas.share_key()

                if message:
                    self.outgoing_to_device_messages.append(message)

            elif isinstance(event, KeyVerificationMac):
                sas.receive_mac_event(event)

                if sas.canceled:
                    message = sas.get_cancellation()
                    self.outgoing_to_device_messages.append(message)
                    return

                logger.info("Received a valid key verification MAC "
                            "from {} {} {}.".format(
                                event.sender,
                                sas.other_olm_device.id,
                                event.transaction_id
                            ))

                if sas.verified:
                    logger.info("Interactive key verification successful, "
                                "verifying device {} of user {} {}.".format(
                                    sas.other_olm_device.id,
                                    event.sender,
                                    event.transaction_id))
                    device = sas.other_olm_device
                    self.verify_device(device)
