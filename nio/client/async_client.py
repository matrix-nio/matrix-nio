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

import asyncio
from asyncio import Event
from functools import partial, wraps
from json.decoder import JSONDecodeError
from typing import (Any, Coroutine, Dict, Iterable, List, Optional, Tuple,
                    Type, Union)
from uuid import uuid4

import attr
from aiohttp import ClientResponse, ClientSession, ContentTypeError
from aiohttp.client_exceptions import ClientConnectionError

from . import Client, ClientConfig, logged_in, store_loaded
from ..api import Api
from ..exceptions import (GroupEncryptionError, LocalProtocolError,
                          MembersSyncError, SendRetryError)
from ..messages import ToDeviceMessage
from ..responses import (JoinedMembersError, JoinedMembersResponse,
                         KeysClaimError, KeysClaimResponse, KeysQueryResponse,
                         KeysUploadResponse, LoginError, LoginResponse,
                         Response, RoomKeyRequestError, RoomKeyRequestResponse,
                         RoomSendResponse, ShareGroupSessionError,
                         ShareGroupSessionResponse, SyncError, SyncResponse,
                         ToDeviceError, ToDeviceResponse)

if False:
    from ..events import MegolmEvent
    from .crypto import OlmDevice

_ShareGroupSessionT = Union[ShareGroupSessionError, ShareGroupSessionResponse]


@attr.s
class ResponseCb(object):
    """Response callback."""

    func = attr.ib()
    filter = attr.ib(default=None)


def client_session(func):
    """Ensure that the Async client has a valid client session."""
    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        if not self.client_session:
            self.client_session = ClientSession()
        return await func(self, *args, **kwargs)
    return wrapper


class AsyncClient(Client):
    """An async IO matrix client.

    Args:
        homeserver (str): The URL of the homeserver which we want to connect
            to.
        user (str, optional): The user which will be used when we log in to the
            homeserver.
        device_id (str, optional): An unique identifier that distinguishes
            this client instance. If not set the server will provide one after
            log in.
        store_path (str, optional): The directory that should be used for state
            storage.
        config (ClientConfig, optional): Configuration for the client.
        ssl (bool/ssl.SSLContext, optional): SSL validation mode. None for
            default SSL check (ssl.create_default_context() is used), False
            for skip SSL certificate validation connection.
        proxy (str, optional): The proxy that should be used for the HTTP
            connection.

    Attributes:
        synced (Event): An asyncio event that is fired every time the client
            successfully syncs with the server.

    Example:
            >>> client = AsyncClient("https://example.org", "example")
            >>> login_response = loop.run_until_complete(
            >>>     client.login("hunter1")
            >>> )

    """

    def __init__(
            self,
            homeserver,     # type: str
            user="",        # type: str
            device_id="",   # type: Optional[str]
            store_path="",  # type: Optional[str]
            config=None,    # type: Optional[ClientConfig]
            ssl=None,       # type: Optional[bool]
            proxy=None,     # type: Optional[str]
    ):
        # type: (...) -> None
        self.homeserver = homeserver
        self.client_session = None  # type: Optional[ClientSession]

        self.ssl = ssl
        self.proxy = proxy

        self.synced = Event()
        self.response_callbacks = []  # type: List[ResponseCb]

        self.sharing_session = dict()  # type: Dict[str, Event]

        super().__init__(user, device_id, store_path, config)

    def add_response_callback(
        self,
        func,           # type: Coroutine[Any, Any, Response]
        cb_filter=None  # type: Union[Tuple[Type], Type, None]
    ):
        # type: (...) -> None
        """Add a coroutine that will be called if a response is received.

        Args:
            func (Coroutine): The coroutine that will be called with the
                response as the argument.
            cb_filter (Type, optional): A type or a tuple of types for which
                the callback should be called.
        """
        cb = ResponseCb(func, cb_filter)
        self.response_callbacks.append(cb)

    async def parse_body(self, transport_response):
        # type: (ClientResponse) -> Dict[Any, Any]
        """Parse the body of the response.

        Args:
            transport_response(ClientResponse): The transport response that
                contains the body of the response.

        Returns a dictionary representing the response.
        """
        try:
            parsed_dict = await transport_response.json()
        except (JSONDecodeError, ContentTypeError):
            parsed_dict = {}

        return parsed_dict

    async def create_matrix_response(
            self,
            response_class,
            transport_response,
            data=None
    ):
        # type: (Type, ClientResponse, Tuple) -> Response
        """Transform a transport response into a nio matrix response.

        Args:
            response_class (Type): The class that the requests belongs to.
            transport_response (ClientResponse): The underlying transport
                response that contains our response body.
            data (Tuple, optional): Extra data that is required to instantiate
                the response class.

        Returns a subclass of `Response` depending on the type of the
        response_class argument.
        """
        parsed_dict = await self.parse_body(transport_response)

        if data:
            response = response_class.from_dict(parsed_dict, *data)
        else:
            response = response_class.from_dict(parsed_dict)

        response.transport_response = transport_response
        return response

    async def _send(
            self,
            response_class,
            method,
            path,
            data=None,
            response_data=None
    ):
        transport_response = await self.send(method, path, data)

        response = await self.create_matrix_response(
            response_class,
            transport_response,
            response_data
        )
        self.receive_response(response)

        return response

    @client_session
    async def send(
            self,
            method,       # type: str
            path,         # type: str
            data=None,    # type: Optional[str]
            headers=None  # type: Optional[Dict[str, str]]
    ):
        # type: (...) -> ClientResponse
        """Send a request to the homeserver.

        Args:
            method (str): The request method that should be used. One of get,
                post, put, delete.
            path (str): The URL path of the request.
            data (str, optional): Data that will be posted with the request.
            headers (Dict[str,str] , optional): Additional request headers that
                should be used with the request.
        """
        assert self.client_session

        return await self.client_session.request(
            method,
            self.homeserver + path,
            data=data,
            ssl=self.ssl,
            proxy=self.proxy,
            headers=headers
        )

    async def login(self, password, device_name=""):
        # type: (str, str) -> Union[LoginResponse, LoginError]
        """Login to the homeserver.

        Args:
            password (str): The user's password.
            device_name (str): A display name to assign to a newly-created
                device. Ignored if the logged in device corresponds to a
                known device.

        Returns either a `LoginResponse` if the request was successful or
        a `LoginError` if there was an error with the request.
        """
        method, path, data = Api.login(
            self.user,
            password,
            device_name=device_name,
            device_id=self.device_id
        )

        return await self._send(LoginResponse, method, path, data)

    @logged_in
    async def sync(
            self,
            timeout=None,     # type: Optional[int]
            sync_filter=None  # type: Optional[Dict[Any, Any]]
    ):
        # type: (...) -> Union[SyncResponse, SyncError]
        """Synchronise the client's state with the latest state on the server.

        Args:
            timeout(int, optional): The maximum time that the server should
                wait for new events before it should return the request
                anyways, in milliseconds.
            filter (Dict[Any, Any], optional): A filter that should be used for
                this sync request.

        Returns either a `SyncResponse` if the request was successful or
        a `SyncError` if there was an error with the request.
        """
        method, path = Api.sync(
            self.access_token,
            since=self.next_batch,
            timeout=timeout,
            filter=sync_filter
        )

        response = await self._send(SyncResponse, method, path)

        self.synced.set()
        self.synced.clear()

        return response

    @logged_in
    async def send_to_device_messages(self):
        # type: () -> List[ToDeviceResponse]
        """Send out outgoing to-device messages."""
        if not self.outgoing_to_device_messages:
            return []

        tasks = []

        for message in self.outgoing_to_device_messages:
            task = asyncio.create_task(self.to_device(message))
            tasks.append(task)

        return await asyncio.gather(*tasks)

    async def run_response_callbacks(self, responses):
        """Run the configured response callbacks for the given responses."""
        for response in responses:
            for cb in self.response_callbacks:
                if (cb.filter is None
                        or isinstance(response, cb.filter)):
                    await cb.func(response)

    @logged_in
    async def sync_forever(self, timeout=None, filter=None):
        """Continuously sync with the configured homeserver.

        This method calls the sync method in a loop. To react to events event
        callbacks should be configured.

        The loop also makes sure to handle other required requests between
        syncs. To react to the responses a request callback should be added.

        Args:
            timeout(int, optional): The maximum time that the server should
                wait for new events before it should return the request
                anyways, in milliseconds.
            filter (Dict[Any, Any], optional): A filter that should be used for
                this sync request.
        """

        while True:
            try:
                responses = []

                responses.append(await self.sync(timeout, filter))

                responses += await self.send_to_device_messages()

                if self.should_upload_keys:
                    responses.append(await self.keys_upload())

                if self.should_query_keys:
                    responses.append(await self.keys_query())

                await self.run_response_callbacks(responses)

            except asyncio.CancelledError:
                break

            except ClientConnectionError:
                await self.run_response_callbacks(responses)

                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    break

    @logged_in
    @store_loaded
    async def start_key_verification(
        self,
        device,     # type: OlmDevice
        tx_id=None  # type: Optional[str]
    ):
        # type: (...) -> Union[ToDeviceResponse, ToDeviceError]
        """Start a interactive key verification with the given device.

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.

        Args:
            device (OlmDevice): An device with which we would like to start the
                interactive key verification process.
        """
        message = self.create_key_verification(device)
        return await self.to_device(message, tx_id)

    @logged_in
    @store_loaded
    async def cancel_key_verification(
        self,
        transaction_id,     # type: OlmDevice
        reject=False,       # type: bool
        tx_id=None          # type: Optional[str]
    ):
        # type: (...) -> Union[ToDeviceResponse, ToDeviceError]
        """Cancel a interactive key verification with the given device.

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
            reject (bool): Is the cancelation reason because we're rejecting
                the short auth string and mark it as mismatching or a normal
                user cancelation.

        Raises a LocalProtocolError no verification process with the given
        transaction ID exists or if reject is True and the short auth string
        couldn't be shown yet because plublic keys weren't yet exchanged.
        """
        if transaction_id not in self.key_verifications:
            raise LocalProtocolError("Key verification with the transaction "
                                     "id {} does not exist.".format(
                                         transaction_id
                                     ))

        sas = self.key_verifications[transaction_id]

        if reject:
            sas.reject_sas()
        else:
            sas.cancel()

        message = sas.get_cancellation()

        return await self.to_device(message, tx_id)

    @logged_in
    @store_loaded
    async def accept_key_verification(self, transaction_id, tx_id=None):
        # type: (str, Optional[str]) -> Union[ToDeviceResponse, ToDeviceError]
        """Accept a key verification start event.

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
        """
        if transaction_id not in self.key_verifications:
            raise LocalProtocolError("Key verification with the transaction "
                                     "id {} does not exist.".format(
                                         transaction_id
                                     ))

        sas = self.key_verifications[transaction_id]

        message = sas.accept_verification()

        return await self.to_device(message, tx_id)

    @logged_in
    @store_loaded
    async def confirm_short_auth_string(self, transaction_id, tx_id=None):
        # type: (str, Optional[str]) -> Union[ToDeviceResponse, ToDeviceError]
        """Confirm a short auth string and mark it as matching.

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
        """
        message = self.confirm_key_verification(transaction_id)
        return await self.to_device(message, tx_id)

    @logged_in
    async def to_device(
            self,
            message,    # type: ToDeviceMessage
            tx_id=None  # type: Optional[str]
    ):
        # type: (...) -> Union[ToDeviceResponse, ToDeviceError]
        """Send a to-device message.

        Args:
            message (ToDeviceMessage): The message that should be sent out.
            tx_id (str, optional): The transaction ID for this message. Should
                be unique.

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.
        """
        uuid = tx_id or uuid4()

        method, path, data = Api.to_device(
            self.access_token,
            message.type,
            message.as_dict(),
            uuid
        )

        return await self._send(
            ToDeviceResponse,
            method,
            path,
            data,
            response_data=(message, )
        )

    @logged_in
    @store_loaded
    async def keys_upload(self):
        """Upload the E2E encryption keys.

        This uploads the long lived session keys as well as the required amount
        of one-time keys.

        Raises LocalProtocolError if the client isn't logged in, if the session
        store isn't loaded or if no encryption keys need to be uploaded.
        """
        if not self.should_upload_keys:
            raise LocalProtocolError("No key upload needed.")

        keys_dict = self.olm.share_keys()

        method, path, data = Api.keys_upload(
            self.access_token,
            keys_dict
        )

        return await self._send(KeysUploadResponse, method, path, data)

    @logged_in
    @store_loaded
    async def keys_query(self):
        # type: () -> Union[KeysQueryResponse]
        """Query the server for user keys.

        This queries the server for device keys of users with which we share an
        encrypted room.

        Raises LocalProtocolError if the client isn't logged in, if the session
        store isn't loaded or if no key query needs to be performed.
        """
        # TODO refactor that out into the base client, and use our knowledge of
        # already queried users to limit the user list.
        user_list = [
            user_id for room in self.rooms.values()
            if room.encrypted for user_id in room.users
        ]

        if not user_list:
            raise LocalProtocolError("No key query required.")

        # TODO pass the sync token here if it's a device update that triggered
        # our need for a key query.
        method, path, data = Api.keys_query(
            self.access_token,
            user_list
        )

        return await self._send(KeysQueryResponse, method, path, data)

    @logged_in
    async def joined_members(self, room_id):
        # type: (str) -> Union[JoinedMembersResponse, JoinedMembersError]
        """Send a message to a room.

        Args:
            room_id(str): The room id of the room for which we wan't to request
                the joined member list.

        Returns either a `JoinedMembersResponse` if the request was successful
        or a `JoinedMembersError` if there was an error with the request.
        """
        method, path = Api.joined_members(
            self.access_token,
            room_id
        )

        return await self._send(
            JoinedMembersResponse,
            method,
            path,
            response_data=(room_id, )
        )

    @logged_in
    async def room_send(
        self,
        room_id,
        message_type,
        content,
        tx_id=None,
        ignore_unverified_devices=False
    ):
        """Send a message to a room.

        Args:
            room_id(str): The room id of the room where the message should be
                sent to.
            message_type(str): A string identifying the type of the message.
            content(Dict[Any, Any]): A dictionary containing the content of the
                message.
            tx_id(str, optional): The transaction ID of this event used to
                uniquely identify this message.
            ignore_unverified_devices(bool): If the room is encrypted and
                contains unverified devices, the devices can be marked as
                ignored here. Ignored devices will still receive encryption
                keys for messages but they won't be marked as verified.

        If the room where the message should be sent is encrypted the message
        will be encrypted before sending.

        This method also makes sure that the room members are fully synced and
        that keys are queried before sending messages to an encrypted room.

        If the method can't sync the state fully to send out an encrypted
        message after a couple of retries it raises `SendRetryError`.

        Raises `LocalProtocolError` if the client isn't logged in.
        """
        async def send(room_id, message_type, content, tx_id):
            if self.olm:
                try:
                    room = self.rooms[room_id]
                except KeyError:
                    raise LocalProtocolError(
                        "No such room with id {} found.".format(room_id)
                    )

                if room.encrypted:
                    message_type, content = self.encrypt(room_id, message_type,
                                                         content)

            method, path, data = Api.room_send(self.access_token, room_id,
                                               message_type, content, tx_id)

            return await self._send(RoomSendResponse, method, path, data,
                                    (room_id, ))

        retries = 5

        uuid = tx_id or uuid4()

        for i in range(retries):
            try:
                return await send(room_id, message_type, content, uuid)
            except GroupEncryptionError:
                sharing_event = self.sharing_session.get(room_id, None)

                if sharing_event:
                    await sharing_event.wait()
                else:
                    share = await self.share_group_session(
                        room_id,
                        ignore_unverified_devices=ignore_unverified_devices
                    )
                    await self.run_response_callbacks([share])

            except MembersSyncError:
                responses = []
                responses.append(await self.joined_members(room_id))

                if self.should_query_keys:
                    responses.append(await self.keys_query())

                await self.run_response_callbacks(responses)

        raise SendRetryError("Max retries exceeded while trying to send "
                             "the message")

    @logged_in
    @store_loaded
    async def keys_claim(
            self,
            user_set  # type: Dict[str, Iterable[str]]
    ):
        # type: (...) -> Union[KeysClaimResponse, KeysClaimError]
        """Claim one-time keys for a set of user and device pairs.

        Args:
            user_set(Dict[str, Iterator[str]]): A dictionary maping from a user
                id to a iterator of device ids. If a user set for a specific
                room is required it can be obtained using the
                `get_missing_sessions()` method.

        Raises LocalProtocolError if the client isn't logged in, if the session
        store isn't loaded, no room with the given room id exists or the room
        isn't an encrypted room.
        """
        method, path, data = Api.keys_claim(
            self.access_token,
            user_set
        )

        return await self._send(KeysClaimResponse, method, path, data)

    @logged_in
    @store_loaded
    async def share_group_session(
            self,
            room_id,                         # type: str
            tx_id=None,                      # type: Optional[str]
            ignore_unverified_devices=False  # type: bool
    ):
        # type: (...) -> _ShareGroupSessionT
        """Share a group session with a room.

        This method sends a group session to members of a room.

        Args:
            room_id(str): The room id of the room where the message should be
                sent to.
            tx_id(str, optional): The transaction ID of this event used to
                uniquely identify this message.
            ignore_unverified_devices(bool): Mark unverified devices as
                ignored. Ignored devices will still receive encryption
                keys for messages but they won't be marked as verified.


        Raises LocalProtocolError if the client isn't logged in, if the session
        store isn't loaded, no room with the given room id exists, the room
        isn't an encrypted room or a key sharing request is already in flight
        for this room.
        """
        assert self.olm

        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError("No such room with id {}".format(room_id))

        if not room.encrypted:
            raise LocalProtocolError("Room with id {} is not encrypted".format(
                room_id))

        if room_id in self.sharing_session:
            raise LocalProtocolError(
                "Already sharing a group session for {}".format(room_id)
            )

        self.sharing_session[room_id] = Event()

        shared_with = set()

        missing_sessions = self.get_missing_sessions(room_id)

        if missing_sessions:
            await self.keys_claim(missing_sessions)

        try:
            while True:
                user_set, to_device_dict = self.olm.share_group_session(
                    room_id,
                    list(room.users.keys()),
                    ignore_missing_sessions=True,
                    ignore_unverified_devices=ignore_unverified_devices
                )

                uuid = tx_id or uuid4()

                method, path, data = Api.to_device(
                    self.access_token,
                    "m.room.encrypted",
                    to_device_dict,
                    uuid
                )

                response = await self._send(
                    ShareGroupSessionResponse,
                    method,
                    path,
                    data,
                    (room_id, user_set)
                )

                if isinstance(response, ShareGroupSessionResponse):
                    shared_with.update(response.users_shared_with)

        except LocalProtocolError:
            return ShareGroupSessionResponse(room_id, shared_with)
        except ClientConnectionError:
            raise
        finally:
            event = self.sharing_session.pop(room_id)
            event.set()

    @logged_in
    @store_loaded
    async def request_room_key(
            self,
            event,       # type: MegolmEvent
            tx_id=None   # type: Optional[str]
    ):
        # type: (...) -> Union[RoomKeyRequestResponse, RoomKeyRequestError]
        """Request a missing room key.

        This sends out a message to other devices requesting a room key from
        them.

        Args:
            event (str): An undecrypted MegolmEvent for which we would like to
                request the decryption key.

        Returns either a `RoomKeyRequestResponse` if the request was successful
        or a `RoomKeyRequestError` if there was an error with the request.

        Raises a LocalProtocolError if the room key was already requested.

        """
        uuid = tx_id or uuid4()

        if event.session_id in self.outgoing_key_requests:
            raise LocalProtocolError("A key sharing request is already sent"
                                     " out for this session id.")

        assert self.user_id
        assert self.device_id

        message = event.as_key_request(self.user_id, self.device_id)

        method, path, data = Api.to_device(
            self.access_token,
            message.type,
            message.as_dict(),
            uuid
        )

        return await self._send(
            RoomKeyRequestResponse,
            method,
            path,
            data,
            (
                event.session_id,
                event.session_id,
                event.room_id,
                event.algorithm
            )
        )

    async def close(self):
        """Close the underlying http session."""
        if self.client_session:
            await self.client_session.close()
            self.client_session = None

    @store_loaded
    async def export_keys(self, outfile, passphrase, count=10000):
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
        assert self.store
        assert self.olm

        loop = asyncio.get_event_loop()

        inbound_group_store = self.store.load_inbound_group_sessions()
        export_keys = partial(self.olm.export_keys_static, inbound_group_store,
                              outfile, passphrase, count)

        await loop.run_in_executor(None, export_keys)

    @store_loaded
    async def import_keys(self, infile, passphrase):
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
        assert self.store
        assert self.olm

        loop = asyncio.get_event_loop()

        import_keys = partial(self.olm.import_keys_static, infile, passphrase)
        sessions = await loop.run_in_executor(None, import_keys)

        for session in sessions:
            # This could be improved by writing everything to db at once at
            # the end
            if self.olm.inbound_group_store.add(session):
                self.store.save_inbound_group_session(session)
