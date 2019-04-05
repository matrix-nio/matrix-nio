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

import attr

from functools import wraps
from typing import (
    Dict,
    List,
    Optional,
    Union,
    Callable,
    Set,
    Any,
    Tuple
)

from logbook import Logger

from ..exceptions import (
    LocalProtocolError,
)
from ..crypto import Olm

from ..log import logger_group
from ..responses import (
    LoginResponse,
    Response,
    SyncResponse,
    SyncType,
    PartialSyncResponse,
    RoomMessagesResponse,
    KeysUploadResponse,
    KeysQueryResponse,
    ErrorResponse,
    ShareGroupSessionResponse,
    KeysClaimResponse,
    JoinedMembersResponse,
    RoomKeyRequestResponse
)

from ..events import (
    Event,
    BadEventType,
    RoomEncryptedEvent,
    MegolmEvent,
    RoomEncryptionEvent
)
from ..rooms import MatrixInvitedRoom, MatrixRoom
from ..store import MatrixStore, DefaultStore

if False:
    from ..crypto import OlmDevice, OutgoingKeyRequest

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
class ClientConfig(object):
    """nio client configuration.

    Attributes:
        store (MatrixStore, optional): The store that should be used for state
            storage.
        store_name: (str, optional): Filename that should be used for the
            store.
        encryption_enabled(bool, optional): Should end to end encryption be
            used.
        pickle_key: (str, optional): A passphrase that will be used to encrypt
            end to end encryption keys.

    """

    store = attr.ib(type=Callable, default=DefaultStore)
    store_name = attr.ib(type=str, default="")
    encryption_enabled = attr.ib(type=bool, default=True)
    pickle_key = attr.ib(type=str, default="DEFAULT_KEY")


class Client(object):
    """Matrix no-IO client.

    Attributes:
       access_token (str): Token authorizing the user with the server. Is set
           after logging in.
       user_id (str): The full mxid of the current user. This is set after
           logging in.
       next_batch(str): The current sync token.
       rooms(Dict[str, MatrixRoom)): A dictionary containing a mapping of room
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
        self.access_token = ""
        self.next_batch = ""

        self.rooms = dict()  # type: Dict[str, MatrixRoom]
        self.invited_rooms = dict()  # type: Dict[str, MatrixRoom]
        self.encrypted_rooms = set()  # type: Set[str]

    @property
    def logged_in(self):
        # type: () -> bool
        """Check if we are logged in.

        Returns True if the client is logged in to the server, False otherwise.
        """
        return True if self.access_token else False

    @property  # type: ignore
    @store_loaded
    def device_store(self):
        """Store containing known devices."""
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
    def outgoing_key_requests(self):
        # type: () -> Dict[str, OutgoingKeyRequest]
        """Our active key requests that we made."""
        return self.olm.outgoing_key_requests if self.olm else dict()

    def load_store(self):
        # type: () -> None
        """Load the session store and olm account.

        Raises LocalProtocolError if the session_path, user_id and devic_id are
            not set.
        """
        if not self.store_path:
            raise LocalProtocolError("Store path is not defined.")

        if not self.user_id:
            raise LocalProtocolError("User id is not set")

        if not self.device_id:
            raise LocalProtocolError("Device id is not set")

        self.store = self.config.store(
            self.user_id,
            self.device_id,
            self.store_path,
            self.config.pickle_key
        )
        assert self.store
        self.olm = Olm(self.user_id, self.device_id, self.store)
        self.encrypted_rooms = self.store.load_encrypted_rooms()

    def room_contains_unverified(self, room_id):
        # type: (str) -> bool
        """Check if a room contains unverified devices.

        Args:
            room_id (str): Room id of the room that should be checked.

        Returns True if the room contains unverified devices, false otherwise.
        Returns False if no Olm session is loaded or if the room isn't
        encrypted.
        """
        room = self.rooms[room_id]

        if not room.encrypted:
            return False

        if not self.olm:
            return False

        for user in room.users:
            if not self.olm.user_fully_verified(user):
                return True

        return False

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
            device (Device): The device which should be added to the trust
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
            device (Device): The device which should be added to the trust
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
            device (Device): The device which should be added to the
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
            device (Device): The device which should be removed from the
                blacklist.

        Returns true if the device was removed, false if it wasn't on the
        blacklist and no removal happened.
        """
        assert self.olm
        return self.olm.unblacklist_device(device)

    def _handle_login(self, response):
        # type: (Union[LoginResponse, ErrorResponse]) -> None
        if isinstance(response, ErrorResponse):
            return

        self.access_token = response.access_token
        self.user_id = response.user_id
        self.device_id = response.device_id

        if self.store_path and (not self.store or not self.olm):
            self.load_store()

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

    def _handle_sync(self, response):
        # type: (SyncType) -> None
        # We already recieved such a sync response, do nothing in that case.
        if self.next_batch == response.next_batch:
            return

        if isinstance(response, SyncResponse):
            self.next_batch = response.next_batch

        encrypted_rooms = set()
        decrypted_to_device = []  # type: ignore

        for index, to_device_event in enumerate(response.to_device_events):
            if isinstance(to_device_event, RoomEncryptedEvent):
                if not self.olm:
                    continue
                event = self.olm.decrypt_event(to_device_event)
                if event:
                    decrypted_to_device.append((index, event))

        # Replace the encrypted to_device events with decrypted ones
        for decrypted_event in decrypted_to_device:
            index, event = decrypted_event
            response.to_device_events[index] = event

        for room_id, info in response.rooms.invite.items():
            if room_id not in self.invited_rooms:
                logger.info("New invited room {}".format(room_id))
                self.invited_rooms[room_id] = MatrixInvitedRoom(
                    room_id, self.user_id
                )

            room = self.invited_rooms[room_id]

            for event in info.invite_state:
                room.handle_event(event)

        for room_id, join_info in response.rooms.join.items():
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
                room.handle_event(event)

            if join_info.summary:
                room.update_summary(join_info.summary)

            decrypted_events = []

            for index, event in enumerate(join_info.timeline.events):
                if isinstance(event, MegolmEvent) and self.olm:
                    event.room_id = room_id
                    new_event = self.olm.decrypt_event(event)
                    if new_event:
                        event = new_event
                        decrypted_events.append((index, new_event))

                elif isinstance(event, RoomEncryptionEvent):
                    encrypted_rooms.add(room_id)

                room.handle_event(event)

            # Replace the Megolm events with decrypted ones
            for decrypted_event in decrypted_events:
                index, event = decrypted_event
                join_info.timeline.events[index] = event

            for event in join_info.ephemeral:
                room.handle_ephemeral_event(event)

            if room.encrypted and self.olm is not None:
                self.olm.update_tracked_users(room)

        self.encrypted_rooms.update(encrypted_rooms)

        if self.store:
            self.store.save_encrypted_rooms(encrypted_rooms)

        if self.olm:
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

    @store_loaded
    def _handle_olm_response(self, response):
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
            room.add_member(member.user_id, member.display_name)

        if room.encrypted and self.olm is not None:
            self.olm.update_tracked_users(room)

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
        elif isinstance(response, (SyncResponse, PartialSyncResponse)):
            self._handle_sync(response)
        elif isinstance(response, RoomMessagesResponse):
            self._handle_messages_response(response)
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
        else:
            pass

    @store_loaded
    def export_keys(self, outfile, passphrase, count=10000):
        # type: (str, str, int) -> None
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

        Returns a tuple containing the new message type and the new encrypted
        content.
        """
        assert self.olm
        content = self.olm.group_encrypt(
            room_id,
            {
                "content": content,
                "type": message_type
            },
        )
        message_type = "m.room.encrypted"

        return message_type, content
