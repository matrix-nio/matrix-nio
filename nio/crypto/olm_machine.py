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
from typing import (Any, DefaultDict, Dict, List, Optional, Set, Tuple, Union, Iterator)

import olm
from jsonschema import SchemaError, ValidationError
from olm import (OlmGroupSessionError, OlmMessage, OlmPreKeyMessage,
                 OlmSessionError)
from cachetools import LRUCache

from . import (DeviceStore, GroupSessionStore, InboundGroupSession,
               InboundSession, OlmAccount, OlmDevice, OutboundGroupSession,
               OutboundSession, Session, SessionStore, logger,
               OutgoingKeyRequest)
from ..api import Api
from ..events import (BadEvent, BadEventType, Event,
                      ForwardedRoomKeyEvent, KeyVerificationAccept,
                      KeyVerificationCancel, KeyVerificationEvent,
                      KeyVerificationKey, KeyVerificationMac,
                      KeyVerificationStart, MegolmEvent, OlmEvent,
                      EncryptedToDeviceEvent, RoomKeyEvent, UnknownBadEvent,
                      DummyEvent, validate_or_badevent, RoomKeyRequest,
                      RoomKeyRequestCancellation)
from ..exceptions import (EncryptionError, GroupEncryptionError,
                          LocalProtocolError, OlmTrustError,
                          OlmUnverifiedDeviceError, VerificationError)
from ..responses import (KeysClaimResponse, KeysQueryResponse,
                         KeysUploadResponse, RoomKeyRequestResponse,
                         ToDeviceResponse)
from ..schemas import Schemas, validate_json
from ..store import MatrixStore
from .key_export import decrypt_and_read, encrypt_and_save
from .sas import Sas
from ..event_builders import ToDeviceMessage, DummyMessage, RoomKeyRequestMessage

try:
    from json.decoder import JSONDecodeError
except ImportError:  # pragma: no cover
    JSONDecodeError = ValueError  # type: ignore


DecryptedOlmT = Union[RoomKeyEvent, BadEvent, UnknownBadEvent, None]


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class KeyShareError(Exception):
    pass


class Olm:
    _olm_algorithm = 'm.olm.v1.curve25519-aes-sha2'
    _megolm_algorithm = 'm.megolm.v1.aes-sha2'
    _algorithms = [_olm_algorithm, _megolm_algorithm]
    _maxToDeviceMessagesPerRequest = 20
    _max_sas_life = timedelta(minutes=20)
    _unwedging_interval = timedelta(minutes=60)

    # To protect against replay attacks we store a bunch of data, as the dict
    # keys we store:
    #   - sender key: a curve25519 public key, 43 bytes
    #   - session id: this is the id of the megolm group session that was
    #       used to encrypt the message, 43 bytes
    #   - message index: an integer representing the current ratchet state, 8
    #       bytes
    # The values of the dict hold:
    #   - event id: for v4/v5 rooms this is a sha256 hash encoded as
    #       base64 + a $ sign as the prefix, 44 bytes total
    #   - server timestamp: the origin server timestamp of the message, an
    #       integer, 8 bytes
    #
    # This totals in 146 bytes per message. The cache has a limit of 100000
    # which results in around 14 MiB of memory in total.
    _message_index_store_size = 100000

    def __init__(
        self,
        user_id,    # type: str
        device_id,  # type: str
        store,      # type: MatrixStore
    ):
        # type: (...) -> None

        # Our own user id and device id. A tuple of user_id/device_id is
        # guaranteed to be unique.
        self.user_id = user_id
        self.device_id = device_id

        # The number of one-time keys we have uploaded on the server. If this
        # is None no action will be taken. After a sync request the client will
        # set this for us and depending on the count we will suggest the client
        # to upload new keys.
        self.uploaded_key_count = None  # type: Optional[int]

        # A set of users for which we need to query their device keys.
        self.users_for_key_query = set()   # type: Set[str]

        # A store holding all the Olm devices of differing users we know about.
        self.device_store = DeviceStore()

        # A store holding all our 1on1 Olm sessions. These sessions are used to
        # exchange encrypted messages between two devices (e.g. encryption keys
        # for room message encryption are shared this way).
        self.session_store = SessionStore()

        # This store holds all the encryption keys that are used to decrypt
        # room messages. An encryption key gets added to the store either if we
        # add our own locally or if it gets shared usin 1on1 Olm sessions with
        # a to-device message with the m.room.encrypted type.
        self.inbound_group_store = GroupSessionStore()

        # This dictionary holds the current encryption key that will be used to
        # encrypt messages for a room. When such a key is created it will be
        # transformed to a InboundGroupSession and stored in the
        # inbound_group_store as well (it will be used to decrypt the messages
        # there). These keys will not be stored permanently, they get rotated
        # relatively frequently. These keys need to be shared with all the
        # users/devices in a room before they can be used to encrypt a room
        # message.
        # Dict of outbound Megolm sessions Dict[room_id]
        self.outbound_group_sessions = {} \
            # type: Dict[str, OutboundGroupSession]

        self.tracked_users = set()  # type: Set[str]

        # A dictionary holding key requests that we sent out ourselves. Those
        # will be stored in the database and restored.
        self.outgoing_key_requests = dict()  \
            # type: Dict[str, OutgoingKeyRequest]

        # This dictionary holds key requests that we received during a sync
        # response. We don't handle them right away since they might be
        # cancelled in the same sync response.
        self.received_key_requests = dict()  # type: Dict[str, RoomKeyRequest]

        # If a received key request comes from a device for which we don't have
        # an Olm session the event will end up in this dictionary and the
        # device will end up in the key_request_devices_no_session list.
        # After the user claims one-time keys for the device with the missing
        # Olm session the event will be put back into the received_key_requests
        # dictionary.
        self.key_requests_waiting_for_session = defaultdict(dict)  \
            # type: Dict[Tuple[str, str], Dict[str, RoomKeyRequest]]
        self.key_request_devices_no_session = list()  # type: List[OlmDevice]

        # This dictionary holds key requests that we received but the device
        # that sent us the key request is not verified/trusted. Such key
        # requests will be forwarded to users using a callback.
        # Users will need to verify the device and tell us to continue the key
        # sharing process using the continue_key_share method.
        self.key_request_from_untrusted = dict()  \
            # type: Dict[str, RoomKeyRequest]

        # A list of devices for which we need to start a new Olm session.
        # Matrix clients need to do a one-time key claiming request for the
        # devices in this list. After a new session is created with the device
        # it will be removed from this list and a dummy encrypted message will
        # be queued to be sent as a to-device message.
        self.wedged_devices = list()  # type: List[OlmDevice]

        # A cache of megolm events that failed to decrypt because the Olm
        # session was wedged and thus the decryption key was missed.
        # We need to unwedge the session and only then send out key re-requests,
        # otherwise we might again fail to decrypt the Olm message.
        self.key_re_requests_events = defaultdict(list)  \
            # type: DefaultDict[Tuple[str, str], List[MegolmEvent]]

        # A mapping from a transaction id to a Sas key verification object. The
        # transaction id uniquely identifies the key verification session.
        self.key_verifications = dict()  # type: Dict[str, Sas]

        # A list of to-device messages that need to be sent to the homeserver
        # by the client. This will get populated by common to-device messages
        # for key-requests, interactive device verification and Olm session
        # unwedging.
        self.outgoing_to_device_messages = []  # type: List[ToDeviceMessage]

        # A least recently used cache for replay attack protection for Megolm
        # encrypted messages. This is a dict holding a tuple of the
        # sender_key, the session id and message index as the key and a tuple
        # of the event_id and origin server timestamp as the dict values.
        self.message_index_store = LRUCache(self._message_index_store_size)

        self.store = store

        # Try to load an account for this user_id/device id tuple from the
        # store.
        account = self.store.load_account()  # type: ignore

        # If no account was found for this user/device create a new one.
        # Otherwise load all the Olm/Megolm sessions and other relevant account
        # data from the store as well.
        if not account:
            logger.info("Creating new Olm account for {} on device {}".format(
                self.user_id, self.device_id))
            account = OlmAccount()
            self.save_account(account)

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

    def _olm_encrypt(self, session, recipient_device, message_type, content):
        payload = {
            "sender": self.user_id,
            "sender_device": self.device_id,

            "keys": {
                "ed25519": self.account.identity_keys["ed25519"]
            },

            "recipient": recipient_device.user_id,
            "recipient_keys": {
                "ed25519": recipient_device.ed25519,
            },

            "type": message_type,
            "content": content
        }

        olm_message = session.encrypt(Api.to_json(payload))
        self.store.save_session(recipient_device.curve25519, session)

        return {
            "algorithm": self._olm_algorithm,
            "sender_key": self.account.identity_keys["curve25519"],
            "ciphertext": {
                recipient_device.curve25519: {
                    "type": olm_message.message_type,
                    "body": olm_message.ciphertext,
                }
            },
        }

    def _queue_dummy_message(self, session, device):
        olm_dict = self._olm_encrypt(session, device, "m.dummy", {})

        logger.info("Queuing a dummy Olm message for device {} of user "
                    "{}".format(device.device_id, device.user_id))

        self.outgoing_to_device_messages.append(
            DummyMessage(
                "m.room.encrypted",
                device.user_id,
                device.device_id,
                olm_dict
            )
        )

    def handle_to_device_event(self, event):
        """Consume to-device events decrypting them if necessary.

        Args:
            event (ToDeviceEvent): The to-device event that should be handled.

        Returns a new event if the event was encrypted and succesfully
        decrypted, otherwise None.
        """
        decrypted_event = None

        if isinstance(event, EncryptedToDeviceEvent):
            decrypted_event = self.decrypt_event(event)
        elif isinstance(event, KeyVerificationEvent):
            self.handle_key_verification(event)
        elif isinstance(event, (RoomKeyRequest, RoomKeyRequestCancellation)):
            self._handle_key_requests(event)

        return decrypted_event

    def _handle_key_requests(self, event):
        # We first queue up all the requests here. This avoids handling of
        # requests that were canceled in the same sync.
        if isinstance(event, RoomKeyRequest):
            # TODO handle differing algorithms better. To achieve this the
            # sessions should know which algorithm they speak.
            if event.algorithm == Olm._megolm_algorithm:
                self.received_key_requests[event.request_id] = event
            else:
                logger.warn("Received key request from {} via {} with an "
                            "unknown algorithm: {}".format(
                                event.sender,
                                event.requesting_device_id,
                                event.algorithm
                            ))

        elif isinstance(event, RoomKeyRequestCancellation):
            # Let us first remove key requests that just arrived. Those don't
            # need anything special.
            self.received_key_requests.pop(event.request_id, None)

            # Now come the key requests that are waiting for an Olm session.
            user_key = (event.sender, event.requesting_device_id)
            self.key_requests_waiting_for_session[user_key].pop(
                event.request_id,
                None
            )

            # If there are no key requests that are waiting for this device to
            # get an Olm session, cancel getting an Olm session as well.
            if not self.key_requests_waiting_for_session[user_key]:
                try:
                    device = (
                        self.device_store[
                            event.sender
                        ][event.requesting_device_id]
                    )
                    self.key_request_devices_no_session.remove(device)
                except (KeyError, ValueError):
                    pass

            # Finally key requests that are waiting for device
            # verification.
            if event.request_id in self.key_request_from_untrusted:
                # First remove the event from our untrusted queue.
                self.key_request_from_untrusted.pop(event.request_id)
                # Since events in the untrusted queue were forwarded to users
                # we need to forward the cancellation as well.
                self.received_key_requests[event.request_id] = event

    def _encrypt_forwarding_key(
        self,
        room_id,         # type: str
        group_session,   # type: InboundGroupSession
        session,         # type: Session
        device           # type: OlmDevice
    ):
        # type: (...) -> ToDeviceMessage
        """Encrypt a group session to be forwarded as a to-device message."""
        key_content = {
            "algorithm": self._megolm_algorithm,
            "forwarding_curve25519_key_chain": group_session.forwarding_chain,
            "room_id": room_id,
            "sender_claimed_ed25519_key": group_session.ed25519,
            "sender_key": group_session.sender_key,
            "session_id": group_session.id,
            "session_key": group_session.export_session(
                group_session.first_known_index
            ),
        }

        olm_dict = self._olm_encrypt(session, device, "m.forwarded_room_key",
                                     key_content)

        return ToDeviceMessage(
            "m.room.encrypted",
            device.user_id,
            device.device_id,
            olm_dict
        )

    def reshare_key(self, event):
        # type: (RoomKeyRequest) -> None
        """Try to reshare an outgoing group session.

        Args:
            event (RoomKeyRequest): The event of the key request.

        If the key share request is valid this will queue up a to-device
        message that holds the room key.

        Raises EncryptionError if no Olm session was found to encrypt
        the key. Raises a KeyShareError if the request was invalid and can't be
        handled.

        """
        logger.debug("Trying to reshare key {} with {}".format(
            event.session_id,
            event.sender
        ))

        outbound_session = self.outbound_group_sessions.get(event.room_id)

        if not outbound_session or outbound_session.id != event.session_id:
            raise KeyShareError("Failed to re-share key {} with {}: No "
                                "outbound session found".format(
                                    event.session_id, event.sender))

        user_tuple = (event.sender, event.requesting_device_id)

        if user_tuple not in outbound_session.users_shared_with:
            raise KeyShareError(
                "Failed to re-share key {} with {}: Session wasn't "
                "shared with the device {}".format(event.session_id,
                                                   event.sender,
                                                   event.requesting_device_id))

        sender_key = self.account.identity_keys["curve25519"]

        group_session = self.inbound_group_store.get(
            event.room_id,
            sender_key,
            outbound_session.id
        )

        # If there is an outbound group session, we are guaranteed to have the
        # inbound one as well.
        assert group_session

        try:
            device = (
                self.device_store[event.sender][event.requesting_device_id]
            )
        except KeyError:
            raise KeyShareError(
                "Failed to re-share key {} with {}: Unknown requesting "
                "device {}.".format(event.session_id, event.sender,
                                    event.requesting_device_id))

        if device.deleted:
            raise KeyShareError(
                "Failed to re-share key {} with {}: Request from a "
                "deleted device {}.".format(event.session_id,
                                            event.sender,
                                            event.requesting_device_id))

        session = self.session_store.get(device.curve25519)

        if not session:
            raise EncryptionError("No Olm session found for {} and device "
                                  "{}".format(device.user_id, device.id))

        logger.debug("Successfully re-shared key {} with {}".format(
            event.session_id,
            event.sender
        ))

        self.outgoing_to_device_messages.append(
            self._encrypt_forwarding_key(
                event.room_id,
                group_session,
                session,
                device
            )
        )

    def share_with_ourselves(self, event):
        # type: (RoomKeyRequest) -> None
        """Share a room key with some other device owned by our own user.

        Args:
            event (RoomKeyRequest): The event of the key request.

        If the key share request is valid this will queue up a to-device
        message that holds the room key.

        Raises EncryptionError if no Olm session was found to encrypt
        the key. Raises OlmTrustError if the device that requested the key is
        not verified. Raises a KeyShareError if the request is invalid and
        can't be handled.
        """
        logger.debug("Trying to share key {} with {}:{}".format(
            event.session_id,
            event.sender,
            event.requesting_device_id
        ))

        group_session = self.inbound_group_store.get(
            event.room_id,
            event.sender_key,
            event.session_id
        )

        if not group_session:
            raise KeyShareError("Failed to re-share key {} with {}: No "
                                "session found".format(event.session_id,
                                                       event.sender))
        try:
            device = (
                self.device_store[event.sender][event.requesting_device_id]
            )
        except KeyError:
            raise KeyShareError(
                "Failed to re-share key {} with {}: Unknown requesting "
                "device {}.".format(event.session_id, event.sender,
                                    event.requesting_device_id))

        session = self.session_store.get(device.curve25519)

        if not session:
            # We need a session for this device first. Put it in a queue for a
            # key claiming request.
            if device not in self.key_request_devices_no_session:
                self.key_request_devices_no_session.append(device)

            # Put our key forward event in a separate queue, key sharing will
            # be retried once a key claim request with the device has been
            # done.
            self.key_requests_waiting_for_session[(
                device.user_id,
                device.device_id
            )][event.request_id] = event

            raise EncryptionError("No Olm session found for {} and device "
                                  "{}".format(device.user_id, device.id))

        if not device.verified:
            raise OlmUnverifiedDeviceError(
                device,
                "Failed to re-share key {} with {}: Device {} is not "
                "verified".format(
                    event.session_id,
                    event.sender,
                    event.requesting_device_id
                )
            )

        logger.debug("Successfully shared a key {} with {}:{}".format(
            event.session_id,
            event.sender,
            event.requesting_device_id
        ))

        self.outgoing_to_device_messages.append(
            self._encrypt_forwarding_key(
                event.room_id,
                group_session,
                session,
                device
            )
        )

    def get_active_key_requests(self, user_id, device_id):
        # type: (str, str) -> List[RoomKeyRequest]
        """Get key requests from a device that are waiting for verification.

        Args:
            user_id (str): The id of the user for which we would like to find
                the active key requests.
            device_id (str): The id of the device for which we would like to
                find the active key requests.
        """
        return [event for event in self.key_request_from_untrusted.values()
                if event.sender == user_id
                and event.requesting_device_id == device_id]

    def continue_key_share(self, event):
        # type: (RoomKeyRequest) -> bool
        """Continue a previously interrupted key share event.

        Args:
            event (RoomKeyRequest): The event which we would like to continue.
        """
        if event not in self.key_request_from_untrusted.values():
            raise LocalProtocolError("No such pending key share request found")

        event = self.key_request_from_untrusted[event.request_id]

        if not self._collect_single_key_share(event):
            return False

        self.key_request_from_untrusted.pop(event.request_id)
        return True

    def cancel_key_share(self, event):
        # type: (RoomKeyRequest) -> bool
        """Cancel a previously interrupted key share event.

        Args:
            event (RoomKeyRequest): The event which we would like to cancel.
        """
        return bool(
            self.key_request_from_untrusted.pop(event.request_id, None)
        )

    def _collect_single_key_share(self, event):
        # type: (RoomKeyRequest) -> bool
        # The sender is ourself but on a different device. We share all
        # keys with ourselves.
        if event.sender == self.user_id:
            try:
                self.share_with_ourselves(event)
            except KeyShareError as error:
                logger.warn(error)
            except EncryptionError as error:
                # We can safely ignore this, the share_with_ourselves
                # method will queue up the device for a key claiming
                # request when that is done the event will be put back
                # in the received_key_requests queue.
                logger.warn(error)
            except OlmTrustError:
                return False

        # The sender is someone else, we share only the current
        # outbound group session.
        else:
            try:
                self.reshare_key(event)
            except (KeyShareError, EncryptionError) as error:
                logger.warn(error)

        return True

    def collect_key_requests(self):
        """Turn queued up key requests into to-device messages for key sharing.

        Returns RoomKeyRequest events that couldn't be sent out because the
        requesting device isn't verified or ignored.
        """
        events_for_users = []

        for event in self.received_key_requests.values():
            # A key request cancellation turning up here means that the
            # cancellation cancelled a key request from an untrusted device.
            # Such a request was presented to the user to do the verification
            # dance before continuing so we need to show the user that the
            # request was cancelled.
            if isinstance(event, RoomKeyRequestCancellation):
                events_for_users.append(event)
                continue

            # The collect_single_key_share method tries to produce to-device
            # messages for the key share request. It will return False if it
            # wasn't able to produce such a to-device message if the requesting
            # device isn't trusted.
            # Forward such requests from untrusted devices to the user so they
            # can verify the device and continue with the key share request or
            # reject the request.
            if not self._collect_single_key_share(event):
                self.key_request_from_untrusted[event.request_id] = event
                events_for_users.append(event)

        self.received_key_requests = dict()
        return events_for_users

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
                    logger.info("Successfully verified signature for one-time "
                                "key of device {} of user {}.".format(
                                    device_id, user_id))
                    logger.info("Creating Outbound Session for device {} of "
                                "user {}".format(device_id, user_id))
                    session = self.create_session(key_object["key"],
                                                  device.curve25519)

                    if device in self.wedged_devices:
                        self.wedged_devices.remove(device)
                        self._queue_dummy_message(session, device)

                    if device in self.key_request_devices_no_session:
                        self.key_request_devices_no_session.remove(device)

                        events = self.key_requests_waiting_for_session.pop(
                            (device.user_id, device.device_id),
                            {}
                        )
                        self.received_key_requests.update(events)

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
                if user_id == self.user_id and device_id == self.device_id:
                    continue

                if (payload['user_id'] != user_id
                        or payload['device_id'] != device_id):
                    logger.warn(
                        "Mismatch in keys payload of device "
                        f"{payload['device_id']} "
                        f"({device_id}) of user {payload['user_id']} "
                        f"({user_id}).",
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

                    if device.curve25519 != curve_key:
                        device.curve25519 = curve_key
                        logger.info("Updating curve key in the device store "
                                    "for user {} with device id {}".format(
                                        user_id, device_id))

                    elif device.display_name != display_name:
                        device.display_name = display_name
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

    def _mark_to_device_message_as_sent(self, message):
        """Mark a to-device message as sent.

        This removes the to-device message from our outgoing to-device list.
        """

        try:
            self.outgoing_to_device_messages.remove(message)

            if isinstance(message, DummyMessage):
                # Queue up key requests to be sent out that happened because of
                # this wedged session.
                events = self.key_re_requests_events.pop((message.recipient, message.recipient_device), [])

                requested_sessions = []

                for event in events:
                    # Don't send out key re-requests for the same session twice.
                    # TODO filter this when putting the events in.
                    if event.session_id in requested_sessions:
                        continue

                    message = event.as_key_request(event.sender, self.device_id,
                                                   event.session_id, event.device_id)
                    logger.info(f"Queuing a room key re-request for a unwedged "
                                f"Olm session: {event.sender} {event.sender} "
                                f"{event.session_id}.")
                    self.outgoing_to_device_messages.append(message)

                    requested_sessions.append(event.session_id)

            elif isinstance(message, RoomKeyRequestMessage):
                key_request = OutgoingKeyRequest.from_message(message)
                self.outgoing_key_requests[message.request_id] = key_request
                self.store.add_outgoing_key_request(key_request)

        except ValueError:
            pass

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

        elif isinstance(response, ToDeviceResponse):
            self._mark_to_device_message_as_sent(response.to_device_message)

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
        # type: (str, str) -> OutboundSession
        # TODO this can fail
        session = OutboundSession(self.account, curve_key, one_time_key)
        # Save the account, add the session to the store and save it to the
        # database.
        self.save_account()
        self.session_store.add(curve_key, session)
        self.save_session(curve_key, session)

        return session

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

    def get_users_for_key_claiming(self):
        # type: () -> Dict[str, List[str]]
        """Get the content for a key claim request that needs to be made.

        Returns a dictionary containing users as the keys and a list of devices
        for which we will claim one-time keys.

        Raises a LocalProtocolError if no key claim request needs to be made.
        """
        if not self.wedged_devices and not self.key_request_devices_no_session:
            raise LocalProtocolError("No wedged sessions found.")

        wedged = defaultdict(list)  # type: DefaultDict[str, List[str]]

        for device in self.wedged_devices:
            wedged[device.user_id].append(device.device_id)

        for device in self.key_request_devices_no_session:
            if device in wedged[device.user_id]:
                continue

            wedged[device.user_id].append(device.device_id)

        return wedged

    def _mark_device_for_unwedging(self, sender, sender_key):
        device = self.device_store.device_from_sender_key(sender, sender_key)

        if not device:
            # TODO we should probably mark this user for a key query.
            logger.warn("Attempted to mark a device for Olm session "
                        "unwedging, but no device was found for user {} with "
                        "sender key {}".format(sender, sender_key))
            return

        session = self.session_store.get(device.curve25519)

        # Don't mark the device to be unwedged if our newest session is less
        # than an hour old.
        if session:
            session_age = datetime.now() - session.creation_time
            if session_age < self._unwedging_interval:
                logger.warn("Attempted to mark device {} of user {} for Olm "
                            "session unwedging, but a new session was created "
                            "recently.".format(
                                device.device_id,
                                device.user_id
                            ))
                return

        if device not in self.wedged_devices:
            logger.info("Marking device {} of user {} as wedged".format(
                device.device_id,
                device.user_id
            ))

            self.wedged_devices.append(device)

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
                    "Successfully decrypted olm message "
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
                        "Decryption failed for matching session"
                    )

                # Decryption failed, we'll try another session in the next
                # iteration.
                logger.info(
                    "Error decrypting olm message from {} "
                    "and sender key {}: {}".format(
                        sender, sender_key, str(e)
                    )
                )

        return None

    def _verify_olm_payload(self, sender, payload):
        # type: (str, Dict[Any, Any]) -> bool
        # Verify that the sender in the payload matches the sender of the event
        if sender != payload["sender"]:
            raise VerificationError("Mismatched sender in Olm payload")

        # Verify that we're the recipient of the payload.
        if self.user_id != payload["recipient"]:
            raise VerificationError("Mismatched recipient in Olm " "payload")

        # Verify that the recipient fingerprint key matches our own
        if (
            self.account.identity_keys["ed25519"]
            != payload["recipient_keys"]["ed25519"]
        ):
            raise VerificationError(
                "Mismatched recipient key in " "Olm payload"
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
                "Error: unsupported room key of type {}".format(
                    event.algorithm
                )
            )
            return event

        logger.info(
            "Received new group session key for room {} "
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
                "Error: unsupported forwarded room key of type {}".format(
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

        if (event.algorithm != key_request.algorithm
                or event.room_id != key_request.room_id
                or event.session_id != key_request.session_id):
            logger.info(
                "Ignoring session key with mismatched algorithm, room_id, or "
                "session id."
            )
            return None

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
        logger.info("Received Olm event of type: {} from {} {}".format(payload["type"], sender, sender_key))

        if payload["type"] == "m.room_key":
            event = self._handle_room_key_event(sender, sender_key, payload)
            return event  # type: ignore

        elif payload["type"] == "m.forwarded_room_key":
            return self._handle_forwarded_room_key_event(
                sender,
                sender_key,
                payload
            )

        elif payload["type"] == "m.dummy":
            return DummyEvent.from_dict(payload, sender, sender_key)

        else:
            logger.warn(
                "Received unsupported Olm event of type {}".format(
                    payload["type"]
                )
            )
            return None

    def message_index_ok(self, message_index, event):
        # type: (int, MegolmEvent) -> bool
        """Check that the message index corresponds to a known message.

        If we know about the index already we will do some sanity checking to
        prevent replay attacks, otherwise we store some info for a later check.

        Args:
            message_index (int): The message index of the decrypted message.
            event (MegolmEvent): The encrypted event that was decrypted and the
                message index belongs to.

        Returns True if the message is ok, False if we found conflicting event
        info indicating a replay attack.
        """
        store_key = (event.sender_key, event.session_id, message_index)

        try:
            event_id, timestamp = self.message_index_store[store_key]
        except KeyError:
            self.message_index_store[store_key] = (
                event.event_id,
                event.server_timestamp
            )
            return True

        if event_id != event.event_id or timestamp != event.server_timestamp:
            return False

        return True

    def check_if_wedged(self, event: MegolmEvent):
        """Check if a Megolm event failed decryption because they keys got lost
        because of a wedged Olm session.
        """
        try:
            device = self.device_store[event.sender][event.device_id]
        except KeyError:
            logger.warn(f"Received a undecryptable Megolm event from a unknown "
                        f"device: {event.sender} {event.device_id}")
            self.users_for_key_query.add(event.sender)
            return

        session = self.session_store.get(device.curve25519)

        if not session:
            logger.warn(f"Received a undecryptable Megolm event from a device "
                        f"with no Olm sessions: {event.sender} {event.device_id}")
            return

        session_age = datetime.now() - session.creation_time

        # We received a undecryptable Megolm event from a device that is
        # currently wedged or has been recently unwedged. If it's recently
        # unwedged send out a key request, otherwise queue up a key request to
        # be sent out after we send the dummy message.
        if (session_age < self._unwedging_interval and
            event.session_id not in self.outgoing_key_requests):
            logger.info(f"Received a undecryptable Megolm event from a device "
                        f"that we recently established an Olm session with: "
                        f"{event.sender} {event.device_id}.")
            message = event.as_key_request(event.sender, self.device_id,
                                           event.session_id, event.device_id)
            self.outgoing_to_device_messages.append(message)

        if device in self.wedged_devices:
            logger.info(f"Received a undecryptable Megolm event from a device "
                        f"that has a wedged Olm session: "
                        f"{event.sender} {event.device_id}.")
            self.key_re_requests_events[(device.user_id, device.device_id)].append(event)

    def _decrypt_megolm_no_error(
        self,
        event: MegolmEvent,
        room_id: str = None
    ) -> Optional[Union[Event, BadEvent]]:
        try:
            return self.decrypt_megolm_event(event, room_id)
        except EncryptionError:
            return None

    def decrypt_megolm_event(self, event, room_id=None):
        # type (MegolmEvent, Optional[str]) -> Union[Event, BadEvent]
        room_id = room_id or event.room_id

        if not room_id:
            raise EncryptionError("Event doesn't contain a room id")

        verified = False

        session = self.inbound_group_store.get(
            room_id,
            event.sender_key,
            event.session_id
        )

        if not session:
            message = (
                "Error decrypting megolm event, no session found "
                "with session id {} for room {}".format(
                    event.session_id,
                    room_id
                )
            )
            self.check_if_wedged(event)
            logger.warn(message)
            raise EncryptionError(message)

        try:
            plaintext, message_index = session.decrypt(event.ciphertext)
        except OlmGroupSessionError as e:
            message = "Error decrypting megolm event: {}".format(str(e))
            logger.warn(message)
            raise EncryptionError(message)

        if not self.message_index_ok(message_index, event):
            raise EncryptionError(
                "Duplicate message index, possible replay attack from {} {} "
                "{}".format(event.sender, event.sender_key, event.session_id)
            )

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
                # to our query set so the client fetches the keys in the next
                # key query.
                self.users_for_key_query.add(event.sender)
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

                    logger.info("Event {} successfully verified".format(
                        event.event_id))
                    verified = True

        try:
            parsed_dict = json.loads(plaintext)  # type: Dict[Any, Any]
        except JSONDecodeError as e:
            raise EncryptionError("Error parsing payload: {}".format(str(e)))

        bad = validate_or_badevent(
            parsed_dict,
            Schemas.room_megolm_decrypted
        )

        if bad:
            return bad

        parsed_dict["event_id"] = event.event_id

        if "m.relates_to" not in parsed_dict["content"]:
            try:
                parsed_dict["content"]["m.relates_to"] = event.source["content"]["m.relates_to"]
            except KeyError:
                pass

        parsed_dict["sender"] = event.sender
        parsed_dict["origin_server_ts"] = event.server_timestamp

        if event.transaction_id:
            parsed_dict["unsigned"] = {
                "transaction_id": event.transaction_id
            }

        new_event = Event.parse_decrypted_event(parsed_dict)

        if isinstance(new_event, UnknownBadEvent):
            return new_event

        new_event.decrypted = True
        new_event.verified = verified
        new_event.sender_key = event.sender_key
        new_event.session_id = event.session_id
        new_event.room_id = room_id

        return new_event

    def decrypt_event(
        self,
        event,  # type: Union[EncryptedToDeviceEvent, MegolmEvent]
        room_id=None  # type: str
    ):
        # type: (...) -> Union[Event, RoomKeyEvent, BadEventType, None]
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
                logger.warn("Unsupported olm message type: {}".format(
                    own_ciphertext["type"]))
                return None

            return self.decrypt(event.sender, event.sender_key, message)

        elif isinstance(event, MegolmEvent):
            try:
                return self.decrypt_megolm_event(event, room_id)
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
            # Mark the device for unwedging instead.
            self._mark_device_for_unwedging(sender, sender_key)
            return None

        # Decryption failed with every known session or no known sessions,
        # let's try to create a new session.
        if plaintext is None:
            # New sessions can only be created if it's a prekey message, we
            # can't decrypt the message if it isn't one at this point in time
            # anymore, so return early
            if not isinstance(message, OlmPreKeyMessage):
                self._mark_device_for_unwedging(sender, sender_key)
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
                self._mark_device_for_unwedging(sender, sender_key)
                return None

        # Mypy complains that the plaintext can still be empty here,
        # realistically this can't happen but let's make mypy happy
        if plaintext is None:
            logger.error("Failed to decrypt Olm message: unknown error")
            return None

        # The plaintext should be valid json, let's parse it and verify it.
        try:
            parsed_payload = json.loads(plaintext)
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
        # is already verified by us
        try:
            self._verify_olm_payload(sender, parsed_payload)

        except VerificationError as e:
            # We found a mismatched property don't process the event any
            # further
            logger.error(e)
            return None

        else:
            # Verification succeeded, handle the event
            return self._handle_olm_event(sender, sender_key, parsed_payload)

    def rotate_outbound_group_session(self, room_id):
        logger.info("Rotating outbound group session for room {}".format(
            room_id))
        self.create_outbound_group_session(room_id)

    def should_share_group_session(self, room_id: str) -> bool:
        """Should the client share a group session.

        Returns True if no session was shared or the session expired, False
        otherwise.
        """
        try:
            session = self.outbound_group_sessions[room_id]
        except KeyError:
            return True

        return session.expired or not session.shared

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

    def share_group_session_parallel(
        self,
        room_id: str,
        users: List[str],
        ignore_unverified_devices: bool = False
    ) -> Iterator[Tuple[Set[Tuple[str, str]], Dict[str, Any]]]:
        logger.info("Sharing group session for room {}".format(room_id))

        if room_id not in self.outbound_group_sessions:
            self.create_outbound_group_session(room_id)

        group_session = self.outbound_group_sessions[room_id]

        if group_session.shared:
            self.create_outbound_group_session(room_id)
            group_session = self.outbound_group_sessions[room_id]

        key_content = {
            "algorithm": self._megolm_algorithm,
            "room_id": room_id,
            "session_id": group_session.id,
            "session_key": group_session.session_key,
        }

        already_shared_set = group_session.users_shared_with
        ignored_set = group_session.users_ignored

        user_map = []
        mark_as_ignored = []

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
                    logger.warn(
                        f"Missing Olm session for user {user_id} and device "
                        f"{device.id}, skipping")
                    continue

                if not self.is_device_verified(device):
                    if self.is_device_ignored(device):
                        pass
                    elif ignore_unverified_devices:
                        mark_as_ignored.append(device)
                    else:
                        raise OlmUnverifiedDeviceError(
                            device,
                            f"Device {device.id} for user {device.user_id} is not "
                            f"verified or blacklisted."
                        )

                user_map.append((user_id, device, session))

        if mark_as_ignored:
            self.store.ignore_devices(mark_as_ignored)

        for user_map_chunk in chunks(user_map, self._maxToDeviceMessagesPerRequest):
            to_device_dict = {"messages": {}}  # type: Dict[str, Any]
            sharing_with = set()

            for user_id, device, session in user_map_chunk:

                olm_dict = self._olm_encrypt(session, device, "m.room_key",
                                             key_content)
                sharing_with.add((user_id, device.id))

                if user_id not in to_device_dict["messages"]:
                    to_device_dict["messages"][user_id] = {}

                to_device_dict["messages"][user_id][device.id] = olm_dict

            yield (sharing_with, to_device_dict)

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
        }

        to_device_dict = {"messages": {}}  # type: Dict[str, Any]

        already_shared_set = group_session.users_shared_with
        ignored_set = group_session.users_ignored

        user_map = []
        mark_as_ignored = []

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
                        mark_as_ignored.append(device)
                    else:
                        raise OlmUnverifiedDeviceError(
                            device,
                            "Device {} for user {} is not "
                            "verified or blacklisted.".format(
                                device.id,
                                device.user_id))

                user_map.append((user_id, device, session))

                if len(user_map) >= self._maxToDeviceMessagesPerRequest:
                    break

            if len(user_map) >= self._maxToDeviceMessagesPerRequest:
                break

        sharing_with = set()

        if mark_as_ignored:
            self.store.ignore_devices(mark_as_ignored)

        for user_id, device, session in user_map:
            olm_dict = self._olm_encrypt(session, device, "m.room_key",
                                         key_content)
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
            "Successfully exported encryption keys to {}".format(outfile)
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

                logger.info("Successfully started key verification with "
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
                to_device_message: Optional[ToDeviceMessage] = None

                if sas.canceled:
                    to_device_message = sas.get_cancellation()
                else:
                    logger.info("Received a key verification pubkey "
                                "from {} {} {}.".format(
                                    event.sender,
                                    sas.other_olm_device.id,
                                    sas.transaction_id))

                if not sas.we_started_it and not sas.canceled:
                    to_device_message = sas.share_key()

                if to_device_message:
                    self.outgoing_to_device_messages.append(to_device_message)

            elif isinstance(event, KeyVerificationMac):
                sas.receive_mac_event(event)

                if sas.canceled:
                    self.outgoing_to_device_messages.append(sas.get_cancellation())
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
