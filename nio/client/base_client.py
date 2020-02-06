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

from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union

import attr
from logbook import Logger
from collections import defaultdict
import warnings

from ..crypto import ENCRYPTION_ENABLED
from ..events import (BadEventType, Event, MegolmEvent,
                      RoomEncryptionEvent, RoomMemberEvent,
                      ToDeviceEvent, RoomKeyRequest,
                      RoomKeyRequestCancellation)
from ..exceptions import LocalProtocolError, MembersSyncError
from ..log import logger_group
from ..responses import (ErrorResponse, JoinedMembersResponse,
                         KeysClaimResponse, KeysQueryResponse,
                         KeysUploadResponse, LoginResponse, LogoutResponse,
                         PartialSyncResponse, Response, RoomContextResponse,
                         RoomForgetResponse, RoomKeyRequestResponse,
                         RoomMessagesResponse, ShareGroupSessionResponse,
                         SyncResponse, SyncType, ToDeviceResponse)
from ..rooms import MatrixInvitedRoom, MatrixRoom

if ENCRYPTION_ENABLED:
    from ..crypto import Olm, DeviceStore
    from ..store import DefaultStore, MatrixStore


if False:
    from ..crypto import OlmDevice, OutgoingKeyRequest, Sas
    from ..event_builders import ToDeviceMessage

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


logger = Logger("nio.client")
logger_group.add_logger(logger)


def logged_in(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.logged_in:
            raise LocalProtocolError("Not logged in.")
        return func(self, *args, **kwargs)
    return wrapper


def store_loaded(fn):
    @wraps(fn)
    def inner(self, *args, **kwargs):
        if not self.store or not self.olm:
            raise LocalProtocolError("Matrix store and olm account is not "
                                     "loaded.")
        return fn(self, *args, **kwargs)
    return inner


@attr.s
class ClientCallback(object):
    """nio internal callback class."""

    func = attr.ib()
    filter = attr.ib()


@attr.s(frozen=True)
class ClientConfig(object):
    """nio client configuration.

    Attributes:
        store (MatrixStore, optional): The store that should be used for state
            storage.
        store_name (str, optional): Filename that should be used for the
            store.
        encryption_enabled (bool, optional): Should end to end encryption be
            used.
        pickle_key (str, optional): A passphrase that will be used to encrypt
            end to end encryption keys.
        store_sync_tokens (bool, optional): Should the client store and restore
            sync tokens.

    Raises an ImportWarning if encryption_enabled is true but the dependencies
    for encryption aren't installed.

    """

    if ENCRYPTION_ENABLED:
        store = attr.ib(type=Callable, default=DefaultStore)
        encryption_enabled = attr.ib(type=bool, default=True)
    else:
        store = attr.ib(type=Callable, default=None)
        encryption_enabled = attr.ib(type=bool, default=False)

    store_name = attr.ib(type=str, default="")
    pickle_key = attr.ib(type=str, default="DEFAULT_KEY")
    store_sync_tokens = attr.ib(type=bool, default=False)

    def __attrs_post_init__(self):
        if not ENCRYPTION_ENABLED and self.encryption_enabled:
            raise ImportWarning("Encryption is enabled in the client "
                                "configuration but dependencies for E2E "
                                "encrytpion aren't installed.")


class Client(object):
    """Matrix no-IO client.

    Attributes:
       access_token (str): Token authorizing the user with the server. Is set
           after logging in.
       user_id (str): The full mxid of the current user. This is set after
           logging in.
       next_batch (str): The current sync token.
       rooms (Dict[str, MatrixRoom)): A dictionary containing a mapping of room
           ids to MatrixRoom objects. All the rooms a user is joined to will be
           here after a sync.

    Args:
       user (str): User that will be used to log in.
       device_id (str, optional): An unique identifier that distinguishes
           this client instance. If not set the server will provide one after
           log in.
       store_dir (str, optional): The directory that should be used for state
           storeage.
       config (ClientConfig, optional): Configuration for the client.

    """

    def __init__(
        self,
        user,            # type: str
        device_id=None,  # type: Optional[str]
        store_path="",  # type: Optional[str]
        config=None,     # type: Optional[ClientConfig]
    ):
        # type: (...) -> None
        self.user = user
        self.device_id = device_id
        self.store_path = store_path
        self.olm = None    # type: Optional[Olm]
        self.store = None  # type: Optional[MatrixStore]
        self.config = config or ClientConfig()

        self.user_id = ""
        # TODO Turn this into a optional string.
        self.access_token = ""  # type: str
        self.next_batch = ""
        self.loaded_sync_token = ""

        self.rooms = dict()  # type: Dict[str, MatrixRoom]
        self.invited_rooms = dict()  # type: Dict[str, MatrixRoom]
        self.encrypted_rooms = set()  # type: Set[str]

        self.event_callbacks = []      # type: List[ClientCallback]
        self.ephemeral_callbacks = []  # type: List[ClientCallback]
        self.to_device_callbacks = []  # type: List[ClientCallback]

    @property
    def logged_in(self):
        # type: () -> bool
        """Check if we are logged in.

        Returns True if the client is logged in to the server, False otherwise.
        """
        return bool(self.access_token)

    @property  # type: ignore
    @store_loaded
    def device_store(self):
        # type: () -> DeviceStore
        """Store containing known devices.

        Returns a ``DeviceStore`` holding all known olm devices.
        """
        assert self.olm
        return self.olm.device_store

    @property  # type: ignore
    @store_loaded
    def olm_account_shared(self):
        """Check if the clients Olm account is shared with the server.

        Returns True if the Olm account is shared, False otherwise.
        """
        return self.olm.account.shared

    @property
    def users_for_key_query(self):
        # type: () -> Set[str]
        """Users for whom we should make a key query."""
        if not self.olm:
            return set()

        return self.olm.users_for_key_query

    @property
    def should_upload_keys(self):
        """Check if the client should upload encryption keys.

        Returns True if encryption keys need to be uploaded, false otherwise.
        """
        if not self.olm:
            return False

        return self.olm.should_upload_keys

    @property
    def should_query_keys(self):
        """Check if the client should make a key query call to the server.

        Returns True if a key query is necessary, false otherwise.
        """
        if not self.olm:
            return False

        return self.olm.should_query_keys

    @property
    def should_claim_keys(self):
        """Check if the client should claim one-time keys for some users.

        This should be periodically checked and if true a keys claim request
        should be made with the return value of a
        `get_users_for_key_claiming()` call as the payload.

        Keys need to be claimed for various reasons. Every time we need to send
        an encrypted message to a device and we don't have a working Olm
        session with them we need to claim one-time keys to create a new Olm
        session.

        Returns True if a key query is necessary, false otherwise.
        """
        if not self.olm:
            return False

        return bool(self.olm.wedged_devices
                    or self.olm.key_request_devices_no_session)

    @property
    def outgoing_key_requests(self):
        # type: () -> Dict[str, OutgoingKeyRequest]
        """Our active key requests that we made."""
        return self.olm.outgoing_key_requests if self.olm else dict()

    @property
    def key_verifications(self):
        # type: () -> Dict[str, Sas]
        """Key verifications that the client is participating in."""
        return self.olm.key_verifications if self.olm else dict()

    @property
    def outgoing_to_device_messages(self):
        # type: () -> List[ToDeviceMessage]
        """To-device messages that we need to send out."""
        return self.olm.outgoing_to_device_messages if self.olm else []

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
        if not self.olm:
            return None

        return self.olm.get_active_sas(user_id, device_id)

    def load_store(self):
        # type: () -> None
        """Load the session store and olm account.

        Raises LocalProtocolError if the session_path, user_id and device_id
            are not set.
        """
        if self.store:
            raise LocalProtocolError("Store is already loaded")

        if not self.store_path:
            raise LocalProtocolError("Store path is not defined.")

        if not self.user_id:
            raise LocalProtocolError("User id is not set")

        if not self.device_id:
            raise LocalProtocolError("Device id is not set")

        if not self.config.store:
            raise LocalProtocolError("No store class was provided in the "
                                     "config.")

        if self.config.encryption_enabled:
            self.store = self.config.store(
                self.user_id,
                self.device_id,
                self.store_path,
                self.config.pickle_key,
                self.config.store_name
            )
            assert self.store

            self.olm = Olm(self.user_id, self.device_id, self.store)
            self.encrypted_rooms = self.store.load_encrypted_rooms()

            if self.config.store_sync_tokens:
                self.loaded_sync_token = self.store.load_sync_token()

    def room_contains_unverified(self, room_id):
        # type: (str) -> bool
        """Check if a room contains unverified devices.

        Args:
            room_id (str): Room id of the room that should be checked.

        Returns True if the room contains unverified devices, false otherwise.
        Returns False if no Olm session is loaded or if the room isn't
        encrypted.
        """
        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError(
                "No room found with room id {}".format(room_id)
            )

        if not room.encrypted:
            return False

        if not self.olm:
            return False

        for user in room.users:
            if not self.olm.user_fully_verified(user):
                return True

        return False

    def _invalidate_session_for_member_event(self, room_id):
        if not self.olm:
            return
        self.invalidate_outbound_session(room_id)

    @store_loaded
    def invalidate_outbound_session(self, room_id):
        """Explicitely remove encryption keys for a room.

        Args:
            room_id (str): Room id for the room the encryption keys should be
                removed.
        """
        session = self.olm.outbound_group_sessions.pop(
            room_id,
            None
        )

        # There is no need to invalidate the session if it was never
        # shared, put it back where it was.
        if session and not session.shared:
            self.olm.outbound_group_sessions[room_id] = session
        elif session:
            logger.info("Invalidating session for {}".format(room_id))

    def _invalidate_outbound_sessions(self, device):
        # type: (OlmDevice) -> None
        assert self.olm

        for room in self.rooms.values():
            if device.user_id in room.users:
                self.invalidate_outbound_session(room.room_id)

    @store_loaded
    def verify_device(self, device):
        # type: (OlmDevice) -> bool
        """Mark a device as verified.

        A device needs to be either trusted or blacklisted to either share room
        encryption keys with it or not.
        This method adds the device to the trusted devices and enables sharing
        room encryption keys with it.

        Args:
            device (OlmDevice): The device which should be added to the trust
                list.

        Returns true if the device was verified, false if it was already
        verified.
        """
        assert self.olm

        changed = self.olm.verify_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    @store_loaded
    def unverify_device(self, device):
        # type: (OlmDevice) -> bool
        """Unmark a device as verified.

        This method removes the device from the trusted devices and disables
        sharing room encryption keys with it. It also invalidates any
        encryption keys for rooms that the device takes part of.

        Args:
            device (OlmDevice): The device which should be added to the trust
                list.

        Returns true if the device was unverified, false if it was already
        unverified.
        """
        assert self.olm

        changed = self.olm.unverify_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    @store_loaded
    def blacklist_device(self, device):
        # type: (OlmDevice) -> bool
        """Mark a device as blacklisted.

        Devices on the blacklist will not receive room encryption keys and
        therefore won't be able to decrypt messages coming from this client.

        Args:
            device (OlmDevice): The device which should be added to the
                blacklist.

        Returns true if the device was added, false if it was on the blacklist
        already.
        """
        assert self.olm

        changed = self.olm.blacklist_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    @store_loaded
    def unblacklist_device(self, device):
        # type: (OlmDevice) -> bool
        """Unmark a device as blacklisted.

        Args:
            device (OlmDevice): The device which should be removed from the
                blacklist.

        Returns true if the device was removed, false if it wasn't on the
        blacklist and no removal happened.
        """
        assert self.olm

        changed = self.olm.unblacklist_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    @store_loaded
    def ignore_device(self, device):
        # type: (OlmDevice) -> bool
        """Mark a device as ignored.

        Ignored devices will still receive room encryption keys, despire not
        being verified.

        Args:
            device (OlmDevice): the device to ignore

        Returns true if device is ignored, or false if it is already on the
        list of ignored devices.
        """
        assert self.olm

        changed = self.olm.ignore_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    @store_loaded
    def unignore_device(self, device):
        # type: (OlmDevice) -> bool
        """Unmark a device as ignored.

        Args:
            device (OlmDevice): The device which should be removed from the
                list of ignored devices.

        Returns true if the device was removed, false if it wasn't on the
        list and no removal happened.
        """
        assert self.olm

        changed = self.olm.unignore_device(device)
        if changed:
            self._invalidate_outbound_sessions(device)

        return changed

    def _handle_login(self, response):
        # type: (Union[LoginResponse, ErrorResponse]) -> None
        if isinstance(response, ErrorResponse):
            return

        self.access_token = response.access_token
        self.user_id = response.user_id
        self.device_id = response.device_id

        if self.store_path and not (self.store and self.olm):
            self.load_store()

    def _handle_logout(self, response):
        # type: (Union[LogoutResponse, ErrorResponse]) -> None
        if not isinstance(response, ErrorResponse):
            self.access_token = ""

    @store_loaded
    def decrypt_event(
        self,
        event  # type: MegolmEvent
    ):
        # type: (...) -> Union[Event, BadEventType]
        """Try to decrypt an undecrypted megolm event.

        Args:
            event (MegolmEvent): Event that should be decrypted.

        Returns the decrypted event, raises EncryptionError if there was an
        error while decrypting.
        """
        if not isinstance(event, MegolmEvent):
            raise ValueError("Invalid event, this function can only decrypt "
                             "MegolmEvents")

        assert self.olm
        return self.olm.decrypt_megolm_event(event)

    def _handle_decrypt_to_device(self, to_device_event):
        if self.olm:
            return self.olm.handle_to_device_event(to_device_event)

        return None

    def _replace_decrypted_to_device(self, decrypted_events, response):
        # Replace the encrypted to_device events with decrypted ones
        for decrypted_event in decrypted_events:
            index, event = decrypted_event
            response.to_device_events[index] = event

    def _run_to_device_callbacks(self, event):
        for cb in self.to_device_callbacks:
            if (cb.filter is None
                    or isinstance(event, cb.filter)):
                cb.func(event)

    def _handle_to_device(self, response):
        decrypted_to_device = []  # type: ignore

        for index, to_device_event in enumerate(response.to_device_events):
            decrypted_event = self._handle_decrypt_to_device(to_device_event)

            if decrypted_event:
                decrypted_to_device.append((index, decrypted_event))
                to_device_event = decrypted_event

            # Do not pass room key request events to our user here. We don't
            # want to notify them about requests that get automatically handled
            # or canceled right away.
            if isinstance(
                to_device_event,
                (RoomKeyRequest, RoomKeyRequestCancellation)
            ):
                continue

            self._run_to_device_callbacks(to_device_event)

        self._replace_decrypted_to_device(decrypted_to_device, response)

    def _get_invited_room(self, room_id):
        if room_id not in self.invited_rooms:
            logger.info("New invited room {}".format(room_id))
            self.invited_rooms[room_id] = MatrixInvitedRoom(
                room_id, self.user_id
            )

        return self.invited_rooms[room_id]

    def _handle_invited_rooms(self, response):
        for room_id, info in response.rooms.invite.items():
            room = self._get_invited_room(room_id)

            for event in info.invite_state:
                room.handle_event(event)

                for cb in self.event_callbacks:
                    if (cb.filter is None or isinstance(event, cb.filter)):
                        cb.func(room, event)

    def _handle_joined_state(self, room_id, join_info, encrypted_rooms):
        if room_id in self.invited_rooms:
            del self.invited_rooms[room_id]

        if room_id not in self.rooms:
            logger.info("New joined room {}".format(room_id))
            self.rooms[room_id] = MatrixRoom(
                room_id,
                self.user_id,
                room_id in self.encrypted_rooms
            )

        room = self.rooms[room_id]

        for event in join_info.state:
            if isinstance(event, RoomEncryptionEvent):
                encrypted_rooms.add(room_id)

            if isinstance(event, RoomMemberEvent):
                if room.handle_membership(event):
                    self._invalidate_session_for_member_event(room_id)
            else:
                room.handle_event(event)

        if join_info.summary:
            room.update_summary(join_info.summary)

    def _handle_timeline_event(self, event, room_id, room, encrypted_rooms):
        decrypted_event = None

        if isinstance(event, MegolmEvent) and self.olm:
            event.room_id = room_id
            decrypted_event = self.olm.decrypt_event(event)

            if decrypted_event:
                event = decrypted_event

        elif isinstance(event, RoomEncryptionEvent):
            encrypted_rooms.add(room_id)

        if isinstance(event, RoomMemberEvent):
            if room.handle_membership(event):
                self._invalidate_session_for_member_event(room_id)
        else:
            room.handle_event(event)

        return decrypted_event

    def _handle_joined_rooms(self, response):
        encrypted_rooms = set()

        for room_id, join_info in response.rooms.join.items():
            self._handle_joined_state(room_id, join_info, encrypted_rooms)

            room = self.rooms[room_id]
            decrypted_events = []

            for index, event in enumerate(join_info.timeline.events):
                decrypted_event = self._handle_timeline_event(
                    event,
                    room_id,
                    room,
                    encrypted_rooms
                )

                if decrypted_event:
                    event = decrypted_event
                    decrypted_events.append((index, decrypted_event))

                for cb in self.event_callbacks:
                    if (cb.filter is None or isinstance(event, cb.filter)):
                        cb.func(room, event)

            # Replace the Megolm events with decrypted ones
            for decrypted_event in decrypted_events:
                index, event = decrypted_event
                join_info.timeline.events[index] = event

            for event in join_info.ephemeral:
                room.handle_ephemeral_event(event)

                for cb in self.ephemeral_callbacks:
                    if (cb.filter is None or isinstance(event, cb.filter)):
                        cb.func(room, event)

            if room.encrypted and self.olm is not None:
                self.olm.update_tracked_users(room)

        self.encrypted_rooms.update(encrypted_rooms)

        if self.store:
            self.store.save_encrypted_rooms(encrypted_rooms)

    def _handle_expired_verifications(self):
        expired_verifications = self.olm.clear_verifications()

        for event in expired_verifications:
            for cb in self.to_device_callbacks:
                if (cb.filter is None
                        or isinstance(event, cb.filter)):
                    cb.func(event)

    def _handle_olm_events(self, response):
        changed_users = set()
        self.olm.uploaded_key_count = (
            response.device_key_count.signed_curve25519)

        for user in response.device_list.changed:
            for room in self.rooms.values():
                if not room.encrypted:
                    continue

                if user in room.users:
                    changed_users.add(user)

        for user in response.device_list.left:
            for room in self.rooms.values():
                if not room.encrypted:
                    continue

                if user in room.users:
                    changed_users.add(user)

        self.olm.add_changed_users(changed_users)

    def _handle_sync(self, response):
        # type: (SyncType) -> None
        # We already recieved such a sync response, do nothing in that case.
        if self.next_batch == response.next_batch:
            return

        if isinstance(response, SyncResponse):
            self.next_batch = response.next_batch

            if self.config.store_sync_tokens and self.store:
                self.store.save_sync_token(self.next_batch)

        self._handle_to_device(response)

        self._handle_invited_rooms(response)

        self._handle_joined_rooms(response)

        if self.olm:
            self._handle_expired_verifications()
            self._handle_olm_events(response)
            self._collect_key_requests()

    def _collect_key_requests(self):
        events = self.olm.collect_key_requests()
        for event in events:
            self._run_to_device_callbacks(event)

    def _decrypt_event_array(self, array):
        if not self.olm:
            return

        decrypted_events = []

        for index, event in enumerate(array):
            if isinstance(event, MegolmEvent):
                new_event = self.olm.decrypt_event(event)
                if new_event:
                    decrypted_events.append((index, new_event))

        for decrypted_event in decrypted_events:
            index, event = decrypted_event
            array[index] = event

    def _handle_context_response(self, response):
        assert isinstance(response, RoomContextResponse)

        if isinstance(response.event, MegolmEvent):
            if self.olm:
                decrypted_event = self.olm.decrypt_event(response.event)
                response.event = decrypted_event

        self._decrypt_event_array(response.events_after)
        self._decrypt_event_array(response.events_before)

    def _handle_messages_response(self, response):
        decrypted_events = []

        for index, event in enumerate(response.chunk):
            if isinstance(event, MegolmEvent) and self.olm:
                new_event = self.olm.decrypt_event(event)
                if new_event:
                    decrypted_events.append((index, new_event))

        for decrypted_event in decrypted_events:
            index, event = decrypted_event
            response.chunk[index] = event

    def _handle_olm_response(self, response):
        if not self.olm:
            return

        self.olm.handle_response(response)

        if isinstance(response, ShareGroupSessionResponse):
            room_id = response.room_id
            session = self.olm.outbound_group_sessions.get(room_id, None)
            room = self.rooms.get(room_id, None)

            session.users_shared_with.update(response.users_shared_with)

            if not session and not room:
                return

            users = room.users

            for user_id in users:
                for device in self.device_store.active_user_devices(user_id):
                    user = (user_id, device.id)
                    if (user not in session.users_shared_with
                            and user not in session.users_ignored):
                        return

            logger.info("Marking outbound group session for room {} "
                        "as shared".format(room_id))
            session.shared = True

        elif isinstance(response, KeysQueryResponse):
            for user_id in response.changed:
                for room in self.rooms.values():
                    if room.encrypted and user_id in room.users:
                        self.invalidate_outbound_session(room.room_id)

    def _handle_joined_members(self, response):
        if response.room_id not in self.rooms:
            return

        room = self.rooms[response.room_id]

        for member in response.members:
            room.add_member(
                member.user_id, member.display_name, member.avatar_url
            )

        if room.encrypted and self.olm is not None:
            self.olm.update_tracked_users(room)

    def _handle_room_forget_response(self, response):
        self.encrypted_rooms.discard(response.room_id)

        if response.room_id in self.rooms:
            room = self.rooms.pop(response.room_id)

            if room.encrypted and self.store:
                self.store.delete_encrypted_room(room.room_id)

        elif response.room_id in self.invited_rooms:
            del self.invited_rooms[response.room_id]

    def receive_response(self, response):
        # type: (Response) -> None
        """Receive a Matrix Response and change the client state accordingly.

        Some responses will get edited for the callers convenience e.g. sync
        responses that contain encrypted messages. The encrypted messages will
        be replaced by decrypted ones if decryption is possible.

        Args:
            response (Response): the response that we wish the client to handle
        """
        if not isinstance(response, Response):
            raise ValueError("Invalid response received")

        if isinstance(response, LoginResponse):
            self._handle_login(response)
        elif isinstance(response, LogoutResponse):
            self._handle_logout(response)
        elif isinstance(response, (SyncResponse, PartialSyncResponse)):
            self._handle_sync(response)
        elif isinstance(response, RoomMessagesResponse):
            self._handle_messages_response(response)
        elif isinstance(response, RoomContextResponse):
            self._handle_context_response(response)
        elif isinstance(response, KeysUploadResponse):
            self._handle_olm_response(response)
        elif isinstance(response, KeysQueryResponse):
            self._handle_olm_response(response)
        elif isinstance(response, KeysClaimResponse):
            self._handle_olm_response(response)
        elif isinstance(response, ShareGroupSessionResponse):
            self._handle_olm_response(response)
        elif isinstance(response, JoinedMembersResponse):
            self._handle_joined_members(response)
        elif isinstance(response, RoomKeyRequestResponse):
            self._handle_olm_response(response)
        elif isinstance(response, RoomForgetResponse):
            self._handle_room_forget_response(response)
        elif isinstance(response, ToDeviceResponse):
            self._handle_olm_response(response)
        elif isinstance(response, ErrorResponse):
            if response.soft_logout:
                self.access_token = ""

    @store_loaded
    def export_keys(self, outfile, passphrase, count=10000):
        # type: (str, str, int) -> None
        """Export all the Megolm decryption keys of this device.

        The keys will be encrypted using the passphrase.

        Note that this does not save other information such as the private
        identity keys of the device.

        Args:
            outfile (str): The file to write the keys to.
            passphrase (str): The encryption passphrase.
            count (int): Optional. Round count for the underlying key
                derivation. It is not recommended to specify it unless
                absolutely sure of the consequences.
        """
        assert self.olm
        self.olm.export_keys(outfile, passphrase, count=count)

    @store_loaded
    def import_keys(self, infile, passphrase):
        # type: (str, str) -> None
        """Import Megolm decryption keys.

        The keys will be added to the current instance as well as written to
        database.

        Args:
            infile (str): The file containing the keys.
            passphrase (str): The decryption passphrase.

        Raises `EncryptionError` if the file is invalid or couldn't be
            decrypted.

        Raises the usual file errors if the file couldn't be opened.
        """
        assert self.olm
        self.olm.import_keys(infile, passphrase)

    @store_loaded
    def get_missing_sessions(self, room_id):
        # type: (str) -> Dict[str, List[str]]
        """Get users and devices for wich we don't have active Olm sessions.

        Args:
            room_id (str): The room id of the room for which we should get the
                users with missing Olm sessions.

        Raises `LocalProtocolError` if the room with the provided room id is
            not found or the room is not encrypted.
        """
        assert self.olm

        if room_id not in self.rooms:
            raise LocalProtocolError("No room found with room id {}".format(
                room_id
            ))
        room = self.rooms[room_id]

        if not room.encrypted:
            raise LocalProtocolError("Room with id {} is not encrypted".format(
                                     room_id))

        return self.olm.get_missing_sessions(list(room.users))

    @store_loaded
    def get_users_for_key_claiming(self):
        # type: () -> Dict[str, List[str]]
        """Get the content for a key claim request that needs to be made.

        Returns a dictionary containing users as the keys and a list of devices
        for which we will claim one-time keys.

        Raises a LocalProtocolError if no key claim request needs to be made.
        """
        assert self.olm
        return self.olm.get_users_for_key_claiming()

    @store_loaded
    def encrypt(self, room_id, message_type, content):
        # type: (str, str, Dict[Any, Any]) -> Tuple[str, Dict[str, str]]
        """Encrypt a message to be sent to the provided room.

        Args:
            room_id (str): The room id of the room where the message will be
                sent.
            message_type (str): The type of the message.
            content (str): The dictionary containing the content of the
                message.

        Raises `GroupEncryptionError` if the group session for the provided
        room isn't shared yet.

        Raises `MembersSyncError` if the room is encrypted but the room members
        aren't fully loaded due to member lazy loading.

        Returns a tuple containing the new message type and the new encrypted
        content.
        """
        assert self.olm

        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError(
                "No such room with id {} found.".format(room_id)
            )

        if not room.encrypted:
            raise LocalProtocolError(
                "Room {} is not encrypted".format(room_id)
            )

        if not room.members_synced:
            raise MembersSyncError("The room is encrypted and the members "
                                   "aren't fully synced.")

        content = self.olm.group_encrypt(
            room_id,
            {
                "content": content,
                "type": message_type
            },
        )
        message_type = "m.room.encrypted"

        return message_type, content

    def add_event_callback(self, callback, filter):
        # type: (Callable[[MatrixRoom, Event], None], Tuple[Type]) -> None
        """Add a callback that will be executed on room events.

        The callback can be used on joined rooms as well as on invited rooms.
        The room parameter for the callback will have a different type
        depending on if the room is joined or invited.

        Args:
            callback (Callable[Union[MatrixRoom, MatrixInvitedRoom, Event]): A
                function that will be called if the event type in the filter
                argument is found in a room timeline.
            filter (Type, Tuple[Type]): The event type or a tuple containing
                multiple types for which the function will be called.

        """
        cb = ClientCallback(callback, filter)
        self.event_callbacks.append(cb)

    def add_ephermeral_callback(self, callback, filter):
        """Deprecated: typo in function name."""
        warnings.warn(
            "deprecated. Use add_ephemeral_callback.",
            DeprecationWarning
        )
        self.add_ephemeral_callback(callback, filter)

    def add_ephemeral_callback(self, callback, filter):
        # type: (Callable[[MatrixRoom, Event], None], Tuple[Type]) -> None
        """Add a callback that will be executed on ephemeral room events.

        Args:
            callback (Callable[MatrixRoom, Event]): A function that will be
                called if the event type in the filter argument is found in the
                ephemeral room event list.
            filter (Type, Tuple[Type]): The event type or a tuple containing
                multiple types for which the function will be called.

        """
        cb = ClientCallback(callback, filter)
        self.ephemeral_callbacks.append(cb)

    def add_to_device_callback(self, callback, filter):
        # type: (Callable[[ToDeviceEvent], None], Tuple[Type]) -> None
        """Add a callback that will be executed on to-device events.

        Args:
            callback (Callable[Event]): A function that will be
                called if the event type in the filter argument is found in a
                the to-device part of the sync response.
            filter (Type, Tuple[Type]): The event type or a tuple containing
                multiple types for which the function will be called.

        """
        cb = ClientCallback(callback, filter)
        self.to_device_callbacks.append(cb)

    @store_loaded
    def create_key_verification(self, device):
        # type: (OlmDevice) -> ToDeviceMessage
        """Start a new key verification process with the given device.

        Args:
            device (OlmDevice): The device which we would like to verify

        Returns a ``ToDeviceMessage`` that should be sent to to the homeserver.
        """
        assert self.olm
        return self.olm.create_sas(device)

    @store_loaded
    def confirm_key_verification(self, transaction_id):
        # type: (str) -> ToDeviceMessage
        """Confirm that the short auth string of a key verification matches.

        Args:
            transaction_id (str): The transaction id of the interactive key
                verification.

        Returns a ``ToDeviceMessage`` that should be sent to to the homeserver.

        If the other user already confirmed the short auth string on their side
        this function will also verify the device that is partaking in the
        verification process.
        """
        if transaction_id not in self.key_verifications:
            raise LocalProtocolError("Key verification with the transaction "
                                     "id {} does not exist.".format(
                                         transaction_id
                                     ))

        sas = self.key_verifications[transaction_id]

        sas.accept_sas()
        message = sas.get_mac()

        if sas.verified:
            self.verify_device(sas.other_olm_device)

        return message

    def room_devices(self, room_id):
        # type (str) -> Dict[str, Dict[str, OlmDevice]]
        """Get all Olm devices participating in a room.

        Args:
            room_id (str): The id of the room for which we would like to
                collect all the devices.

        Returns a dictionary holding the user as the key and a dictionary of
        the device id as the key and OlmDevice as the value.

        Raises LocalProtocolError if no room is found with the given room_id.
        """
        devices = defaultdict(dict)

        if not self.olm:
            return devices

        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError(
                "No room found with room id {}".format(room_id)
            )

        if not room.encrypted:
            return devices

        users = room.users.keys()

        for user in users:
            user_devices = self.device_store.active_user_devices(user)
            devices[user] = {d.id: d for d in user_devices}

        return devices

    @store_loaded
    def get_active_key_requests(self, user_id, device_id):
        # type: (str, str) -> List[RoomKeyRequest]
        """Get key requests from a device that are waiting for verification.

        Args:
            user_id (str): The id of the user for which we would like to find
                the active key requests.
            device_id (str): The id of the device for which we would like to
                find the active key requests.

        Example:
            >>> # A to-device callback that verifies devices that
            >>> # request room keys and continues the room key sharing process.
            >>> # Note that a single user/device can have multiple key requests
            >>> # queued up.
            >>>   def key_share_cb(event):
            ...       user_id = event.sender
            ...       device_id = event.requesting_device_id
            ...       device = client.device_store[user_id][device_id]
            ...       client.verify_device(device)
            ...       for request in client.get_active_key_requests(
            ...           user_id, device_id):
            ...           client.continue_key_share(request)
            >>>   client.add_to_device_callback(key_share_cb)

        Returns:
            list: A list of actively waiting key requests from the given user.

        """
        assert self.olm
        return self.olm.get_active_key_requests(user_id, device_id)

    @store_loaded
    def continue_key_share(self, event):
        # type: (RoomKeyRequest) -> bool
        """Continue a previously interrupted key share event.

        To handle room key requests properly client users need to add a
        callback for RoomKeyRequest:

            >>> client.add_to_device_callback(callback, RoomKeyRequest)

        This callback will be run only if a room key request needs user
        interaction, that is if a room key request is coming from an untrusted
        device.

        After a user has verified the requesting device the key sharing can be
        continued using this method:

            >>> client.continue_key_share(room_key_request)

        Args:
            event (RoomKeyRequest): The event which we would like to continue.

        If the key share event is continued successfully a to-device message
        will be queued up in the `client.outgoing_to_device_messages` list
        waiting to be sent out

        Returns:
            bool: True if the request was continued, False otherwise.

        """
        assert self.olm
        return self.olm.continue_key_share(event)

    @store_loaded
    def cancel_key_share(self, event):
        # type: (RoomKeyRequest) -> bool
        """Cancel a previously interrupted key share event.

        This method is the counterpart to the `continue_key_share()` method. If
        a user choses not to verify a device and does not want to share room
        keys with such a device it should cancel the request with this method.

            >>> client.cancel_key_share(room_key_request)

        Args:
            event (RoomKeyRequest): The event which we would like to cancel.

        Returns:
            bool: True if the request was cancelled, False otherwise.

        """
        assert self.olm
        return self.olm.cancel_key_share(event)
