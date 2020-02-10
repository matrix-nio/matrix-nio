# -*- coding: utf-8 -*-

# Copyright © 2018, 2019 Damir Jelić <poljar@termina.org.uk>
# Copyright © 2020 Famedly GmbH
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
import io
import warnings
from asyncio import Event
from functools import partial, wraps
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import (Any, AsyncIterable, BinaryIO, Callable, Coroutine, Dict,
                    Iterable, List, Optional, Sequence, Tuple, Type, Union)
from uuid import UUID, uuid4

import attr
from aiofiles.threadpool.binary import AsyncBufferedReader
from aiohttp import (ClientResponse, ClientSession, ContentTypeError,
                     TraceConfig)
from aiohttp.client_exceptions import ClientConnectionError

from . import Client, ClientConfig
from .base_client import logged_in, store_loaded
from ..api import (Api, MessageDirection, ResizingMethod, RoomVisibility,
                   RoomPreset)
from ..crypto import (AsyncDataT, async_encrypt_attachment,
                      async_generator_from_data)
from ..exceptions import (GroupEncryptionError, LocalProtocolError,
                          MembersSyncError, SendRetryError,
                          TransferCancelledError)
from ..events import RoomKeyRequest, RoomKeyRequestCancellation
from ..event_builders import ToDeviceMessage
from ..monitors import TransferMonitor
from ..responses import (DeleteDevicesError, DeleteDevicesResponse,
                         DeleteDevicesAuthResponse,
                         DevicesError, DevicesResponse,
                         DownloadError, DownloadResponse,
                         ErrorResponse, FileResponse,
                         JoinResponse, JoinError,
                         JoinedMembersError, JoinedMembersResponse,
                         JoinedRoomsError, JoinedRoomsResponse,
                         KeysClaimError, KeysClaimResponse, KeysQueryResponse,
                         KeysUploadResponse, LoginError, LoginResponse,
                         LogoutError, LogoutResponse,
                         ProfileGetAvatarResponse, ProfileGetAvatarError,
                         ProfileGetDisplayNameResponse,
                         ProfileGetDisplayNameError, ProfileGetResponse,
                         ProfileGetError, ProfileSetAvatarResponse,
                         ProfileSetAvatarError, ProfileSetDisplayNameResponse,
                         ProfileSetDisplayNameError, Response,
                         RoomContextError, RoomContextResponse,
                         RoomCreateResponse, RoomCreateError,
                         RoomForgetResponse, RoomForgetError,
                         RoomInviteResponse, RoomInviteError,
                         RoomKeyRequestError, RoomKeyRequestResponse,
                         RoomLeaveResponse, RoomLeaveError,
                         RoomMessagesError, RoomMessagesResponse,
                         RoomGetStateError, RoomGetStateResponse,
                         RoomGetStateEventError, RoomGetStateEventResponse,
                         RoomPutStateError, RoomPutStateResponse,
                         RoomRedactError, RoomRedactResponse,
                         RoomResolveAliasError, RoomResolveAliasResponse,
                         RoomSendResponse, RoomTypingResponse, RoomTypingError,
                         ShareGroupSessionError,
                         ShareGroupSessionResponse, SyncError, SyncResponse,
                         PartialSyncResponse,
                         ThumbnailError, ThumbnailResponse,
                         ToDeviceError, ToDeviceResponse,
                         UploadError, UploadResponse)

if False:
    from ..events import MegolmEvent
    from .crypto import OlmDevice

_ShareGroupSessionT = Union[ShareGroupSessionError, ShareGroupSessionResponse]

_ProfileGetDisplayNameT = Union[
    ProfileGetDisplayNameResponse,
    ProfileGetDisplayNameError
]
_ProfileSetDisplayNameT = Union[
    ProfileSetDisplayNameResponse,
    ProfileSetDisplayNameError
]

DataProvider = Callable[[int, int], AsyncDataT]


@attr.s
class ResponseCb(object):
    """Response callback."""

    func = attr.ib()
    filter = attr.ib(default=None)


async def on_request_chunk_sent(session, context, params):
    """TraceConfig callback to run when a chunk is sent for client uploads."""

    context_obj = context.trace_request_ctx

    if isinstance(context_obj, TransferMonitor):
        context_obj.transferred += len(params.chunk)


def client_session(func):
    """Ensure that the Async client has a valid client session."""

    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        if not self.client_session:
            trace = TraceConfig()
            trace.on_request_chunk_sent.append(on_request_chunk_sent)

            self.client_session = ClientSession(trace_configs=[trace])

        return await func(self, *args, **kwargs)

    return wrapper


@attr.s(frozen=True)
class AsyncClientConfig(ClientConfig):
    """Async nio client configuration.

    Attributes:
        max_limit_exceeded (int, optional): How many 429 (Too many requests)
            errors can a request encounter before giving up and returning
            an ErrorResponse.
            Default is None for unlimited.

        max_timeouts (int, optional): How many timeout connection errors can
            a request encounter before giving up and raising the error:
            a ClientConnectionError, TimeoutError, or asyncio.TimeoutError.
            Default is None for unlimited.

        backoff_factor (float): A backoff factor to apply between retries
            for timeouts, starting from the second try.
            nio will sleep for `backoff_factor * (2 ** (total_retries - 1))`
            seconds.
            For example, with the default backoff_factor of 0.1,
            nio will sleep for 0.0, 0.2, 0.4, ... seconds between retries.

        max_timeout_retry_wait_time (float): The maximum time to wait between
            retries for timeouts, by default 60.
    """

    max_limit_exceeded = attr.ib(type=Optional[int], default=None)
    max_timeouts = attr.ib(type=Optional[int], default=None)
    backoff_factor = attr.ib(type=float, default=0.1)
    max_timeout_retry_wait_time = attr.ib(type=float, default=60)


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
        config (AsyncClientConfig, optional): Configuration for the client.
        ssl (bool/ssl.SSLContext, optional): SSL validation mode. None for
            default SSL check (ssl.create_default_context() is used), False
            for skip SSL certificate validation connection.
        proxy (str, optional): The proxy that should be used for the HTTP
            connection.

    Attributes:
        synced (Event): An asyncio event that is fired every time the client
            successfully syncs with the server.

    A simple example can be found bellow.

    Example:
            >>> client = AsyncClient("https://example.org", "example")
            >>> login_response = loop.run_until_complete(
            >>>     client.login("hunter1")
            >>> )
            >>> asyncio.run(client.sync_forever(30000))

    This example assumes a full sync on every run. If a sync token is provided
    for the `since` parameter of the `sync_forever` method `full_state` should
    be set to `True` as well.

    Example:
            >>> asyncio.run(
            >>>     client.sync_forever(30000, since="token123",
            >>>                         full_state=True)
            >>> )

    The client can also be configured to store and restore the sync token
    automatically. The `full_state` argument should be set to `True` in that
    case as well.

    Example:
            >>> config = ClientConfig(store_sync_tokens=True)
            >>> client = AsyncClient("https://example.org", "example",
            >>>                      store_path="/home/example",
            >>>                      config=config)
            >>> login_response = loop.run_until_complete(
            >>>     client.login("hunter1")
            >>> )
            >>> asyncio.run(client.sync_forever(30000, full_state=True))

    """

    def __init__(
            self,
            homeserver,     # type: str
            user="",        # type: str
            device_id="",   # type: Optional[str]
            store_path="",  # type: Optional[str]
            config=None,    # type: Optional[AsyncClientConfig]
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

        is_config       = isinstance(config, ClientConfig)
        is_async_config = isinstance(config, AsyncClientConfig)

        if is_config and not is_async_config:
            warnings.warn(
                "Pass an AsyncClientConfig instead of ClientConfig.",
                DeprecationWarning
            )
            config = AsyncClientConfig(**config.__dict__)

        self.config = config or AsyncClientConfig()  # type: AsyncClientConfig

        super().__init__(user, device_id, store_path, self.config)

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

        Example:

            >>> # A callback that will be called every time our `sync_forever`
            >>> # method succesfully syncs with the server.
            >>> async def sync_cb(response):
            ...    print(f"We synced, token: {response.next_batch}")
            ...
            >>> client.add_response_callback(sync_cb, SyncResponse)
            >>> await client.sync_forever(30000)

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
            return await transport_response.json()
        except (JSONDecodeError, ContentTypeError):
            return {}

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
        data = data or ()

        content_type = transport_response.content_type
        is_json = content_type == "application/json"

        name = None
        if transport_response.content_disposition:
            name = transport_response.content_disposition.filename

        if issubclass(response_class, FileResponse) and is_json:
            parsed_dict = await self.parse_body(transport_response)
            resp = response_class.from_data(parsed_dict, content_type, name)

        elif issubclass(response_class, FileResponse):
            body = await transport_response.read()
            resp = response_class.from_data(body, content_type, name)

        elif (transport_response.status == 401
                and response_class == DeleteDevicesResponse):
            parsed_dict = await self.parse_body(transport_response)
            resp = DeleteDevicesAuthResponse.from_dict(parsed_dict)

        else:
            parsed_dict = await self.parse_body(transport_response)
            resp = response_class.from_dict(parsed_dict, *data)

        resp.transport_response = transport_response
        return resp

    async def _run_to_device_callbacks(self, event):
        for cb in self.to_device_callbacks:
            if (cb.filter is None
                    or isinstance(event, cb.filter)):
                await asyncio.coroutine(cb.func)(event)

    async def _handle_to_device(self, response):
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

            await self._run_to_device_callbacks(to_device_event)

        self._replace_decrypted_to_device(decrypted_to_device, response)

    async def _handle_invited_rooms(self, response):
        for room_id, info in response.rooms.invite.items():
            room = self._get_invited_room(room_id)

            for event in info.invite_state:
                room.handle_event(event)

                for cb in self.event_callbacks:
                    if (cb.filter is None or isinstance(event, cb.filter)):
                        await asyncio.coroutine(cb.func)(room, event)

    async def _handle_joined_rooms(self, response):
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
                        await asyncio.coroutine(cb.func)(room, event)

            # Replace the Megolm events with decrypted ones
            for decrypted_event in decrypted_events:
                index, event = decrypted_event
                join_info.timeline.events[index] = event

            for event in join_info.ephemeral:
                room.handle_ephemeral_event(event)

                for cb in self.ephemeral_callbacks:
                    if (cb.filter is None or isinstance(event, cb.filter)):
                        await asyncio.coroutine(cb.func)(room, event)

            if room.encrypted and self.olm is not None:
                self.olm.update_tracked_users(room)

        self.encrypted_rooms.update(encrypted_rooms)

        if self.store:
            self.store.save_encrypted_rooms(encrypted_rooms)

    async def _handle_expired_verifications(self):
        expired_verifications = self.olm.clear_verifications()

        for event in expired_verifications:
            for cb in self.to_device_callbacks:
                if (cb.filter is None
                        or isinstance(event, cb.filter)):
                    await asyncio.coroutine(cb.func)(event)

    async def _handle_sync(self, response):
        # We already recieved such a sync response, do nothing in that case.
        if self.next_batch == response.next_batch:
            return

        if isinstance(response, SyncResponse):
            self.next_batch = response.next_batch

            if self.config.store_sync_tokens and self.store:
                self.store.save_sync_token(self.next_batch)

        await self._handle_to_device(response)

        await self._handle_invited_rooms(response)

        await self._handle_joined_rooms(response)

        if self.olm:
            await self._handle_expired_verifications()
            self._handle_olm_events(response)
            await self._collect_key_requests()

    async def _collect_key_requests(self):
        events = self.olm.collect_key_requests()
        for event in events:
            await self._run_to_device_callbacks(event)

    async def receive_response(self, response):
        """Receive a Matrix Response and change the client state accordingly.

        Some responses will get edited for the callers convenience e.g. sync
        responses that contain encrypted messages. The encrypted messages will
        be replaced by decrypted ones if decryption is possible.

        Args:
            response (Response): the response that we wish the client to handle
        """
        if not isinstance(response, Response):
            raise ValueError("Invalid response received")

        if isinstance(response, (SyncResponse, PartialSyncResponse)):
            await self._handle_sync(response)
        else:
            super().receive_response(response)

    async def get_timeout_retry_wait_time(self, got_timeouts):
        # type: (int) -> float
        if got_timeouts < 2:
            return 0.0

        return min(
            self.config.backoff_factor * (2 ** (got_timeouts - 1)),
            self.config.max_timeout_retry_wait_time
        )

    async def _send(
        self,
        response_class,
        method,
        path,
        data          = None,
        response_data = None,
        content_type  = None,
        trace_context = None,
        data_provider: Optional[DataProvider] = None,
    ):
        headers = {"content-type": content_type} if content_type else {}

        got_429 = 0
        max_429 = self.config.max_limit_exceeded

        got_timeouts = 0
        max_timeouts = self.config.max_timeouts

        while True:
            if data_provider:
                data = data_provider(got_429, got_timeouts)

            try:
                transport_resp = await self.send(
                    method, path, data, headers, trace_context,
                )

                resp = await self.create_matrix_response(
                    response_class,
                    transport_resp,
                    response_data,
                )

                if isinstance(resp, ErrorResponse) and resp.retry_after_ms:
                    got_429 += 1

                    if max_429 is not None and got_429 > max_429:
                        break

                    await self.run_response_callbacks([resp])
                    await asyncio.sleep(resp.retry_after_ms / 1000)
                else:
                    break

            except (ClientConnectionError, TimeoutError, asyncio.TimeoutError):
                got_timeouts += 1

                if max_timeouts is not None and got_timeouts > max_timeouts:
                    raise

                wait = await self.get_timeout_retry_wait_time(got_timeouts)
                await asyncio.sleep(wait)

        await self.receive_response(resp)
        return resp

    @client_session
    async def send(
        self,
        method:        str,
        path:          str,
        data:          Union[None, str, AsyncDataT] = None,
        headers:       Optional[Dict[str, str]]     = None,
        trace_context: Any                          = None,
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
            trace_context (Any, optional): An object to use for the
                ClientSession TraceConfig context
        """
        assert self.client_session

        return await self.client_session.request(
            method,
            self.homeserver + path,
            data              = data,
            ssl               = self.ssl,
            proxy             = self.proxy,
            headers           = headers,
            trace_request_ctx = trace_context,
        )

    async def mxc_to_http(
        self, mxc: str, homeserver: Optional[str] = None,
   ) -> Optional[str]:
        """Convert a matrix content URI to a HTTP URI."""
        return Api.mxc_to_http(mxc, homeserver or self.homeserver)

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
            password=password,
            device_name=device_name,
            device_id=self.device_id
        )

        return await self._send(LoginResponse, method, path, data)

    @logged_in
    async def logout(self, all_devices=False):
        """Logout from the homeserver.

        Returns either 'LogoutResponse' if the request was successful or
        a `Logouterror` if there was an error with the request.
        """
        method, path, data = Api.logout(
            self.access_token,
            all_devices
        )

        return await self._send(LogoutResponse, method, path, data)

    @logged_in
    async def sync(
            self,
            timeout=None,      # type: Optional[int]
            sync_filter=None,  # type: Optional[Dict[Any, Any]]
            since=None,        # type: Optional[str]
            full_state=None    # type: Optional[bool]
    ):
        # type: (...) -> Union[SyncResponse, SyncError]
        """Synchronise the client's state with the latest state on the server.

        Args:
            timeout(int, optional): The maximum time that the server should
                wait for new events before it should return the request
                anyways, in milliseconds.
            sync_filter (Dict[Any, Any], optional): A filter that should be
                used for this sync request.
            full_state(bool, optional): Controls whether to include the full
                state for all rooms the user is a member of. If this is set to
                true, then all state events will be returned, even if since is
                non-empty. The timeline will still be limited by the since
                parameter.
            since(str, optional): A token specifying a point in time where to
                continue the sync from. Defaults to the last sync token we
                received from the server using this API call.

        Returns either a `SyncResponse` if the request was successful or
        a `SyncError` if there was an error with the request.
        """

        sync_token = since or self.next_batch
        method, path = Api.sync(
            self.access_token,
            since=sync_token or self.loaded_sync_token,
            timeout=timeout,
            filter=sync_filter,
            full_state=full_state
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
            task = asyncio.ensure_future(self.to_device(message))
            tasks.append(task)

        return await asyncio.gather(*tasks)

    async def run_response_callbacks(self, responses):
        """Run the configured response callbacks for the given responses."""
        for response in responses:
            for cb in self.response_callbacks:
                if (cb.filter is None
                        or isinstance(response, cb.filter)):
                    await asyncio.coroutine(cb.func)(response)

    @logged_in
    async def sync_forever(
            self,
            timeout=None,         # type: Optional[int]
            sync_filter=None,     # type: Optional[Dict[Any, Any]]
            since=None,           # type: Optional[str]
            full_state=None,      # type: Optional[bool]
            loop_sleep_time=None  # type: Optional[int]
    ):
        # type: (...) -> None
        """Continuously sync with the configured homeserver.

        This method calls the sync method in a loop. To react to events event
        callbacks should be configured.

        The loop also makes sure to handle other required requests between
        syncs. To react to the responses a response callback should be added.

        Args:
            timeout (int, optional): The maximum time that the server should
                wait for new events before it should return the request
                anyways, in milliseconds.
            sync_filter (Dict[Any, Any], optional): A filter that should be
                used for this sync request.
            full_state (bool, optional): Controls whether to include the full
                state for all rooms the user is a member of. If this is set to
                true, then all state events will be returned, even if since is
                non-empty. The timeline will still be limited by the since
                parameter. This argument will be used only for the first sync
                request.
            since (str, optional): A token specifying a point in time where to
                continue the sync from. Defaults to the last sync token we
                received from the server using this API call. This argument
                will be used only for the first sync request, the subsequent
                sync requests will use the token from the last sync response.
            loop_sleep_time (int, optional): The sleep time, if any, between
                successful sync loop iterations in milliseconds.

        """
        while True:
            try:
                tasks = [
                    asyncio.ensure_future(coro) for coro in (
                        self.sync(timeout, sync_filter, since, full_state),
                        self.send_to_device_messages()
                    )
                ]

                if self.should_upload_keys:
                    tasks.append(asyncio.ensure_future(self.keys_upload()))

                if self.should_query_keys:
                    tasks.append(asyncio.ensure_future(self.keys_query()))

                if self.should_claim_keys:
                    tasks.append(asyncio.ensure_future(
                        self.keys_claim(self.get_users_for_key_claiming())
                    ))

                for response in asyncio.as_completed(tasks):
                    await self.run_response_callbacks((await response,))

                full_state = None
                since = None

                if loop_sleep_time:
                    await asyncio.sleep(loop_sleep_time / 1000)

            except asyncio.CancelledError:
                for task in tasks:
                    task.cancel()

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

        Returns either a `ToDeviceResponse` if the request was successful or
        a `ToDeviceError` if there was an error with the request.

        Args:
            message (ToDeviceMessage): The message that should be sent out.
            tx_id (str, optional): The transaction ID for this message. Should
                be unique.
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
        user_list = self.users_for_key_query

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
    async def devices(self) -> Union[DevicesResponse, DevicesError]:
        """Get the list of devices for the current user.

        Returns either a `DevicesResponse` if the request was successful
        or a `DevicesError` if there was an error with the request.
        """
        method, path = Api.devices(self.access_token)

        return await self._send(DevicesResponse, method, path)

    @logged_in
    async def delete_devices(
            self,
            devices: List[str],
            auth:    Optional[Dict[str, str]] = None
    ) -> Union[DeleteDevicesResponse, DeleteDevicesError]:
        """Delete a list of devices.

        This tells the server to delete the given devices and invalidate their
        associated access tokens.

        Returns either a `DeleteDevicesResponse` if the request was successful
        or a `DeleteDevicesError` if there was an error with the request.

        This endpoint supports user-interactive auth, calling this method
        without an auth dictionary will return a `DeleteDevicesAuthResponse`
        which can be used to introspect the valid authentication methods that
        the server supports.

        Args:
            devices (List[str]): A list of devices which will be deleted.
            auth (Dict): Additional authentication information for
                the user-interactive authentication API.

        Example:
            >>> devices = ["QBUAZIFURK", "AUIECTSRND"]
            >>> auth = {"type": "m.login.password",
            ...         "user": "example",
            ...         "password": "hunter1"}
            >>> await client.delete_devices(devices, auth)


        """
        method, path, data = Api.delete_devices(
            self.access_token,
            devices,
            auth_dict=auth
        )

        return await self._send(
            DeleteDevicesResponse,
            method,
            path,
            data
        )

    @logged_in
    async def joined_members(self, room_id):
        # type: (str) -> Union[JoinedMembersResponse, JoinedMembersError]
        """Get the list of joined members for a room.

        Returns either a `JoinedMembersResponse` if the request was successful
        or a `JoinedMembersError` if there was an error with the request.

        Args:
            room_id(str): The room id of the room for which we wan't to request
                the joined member list.
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
    async def joined_rooms(self):
        # type: () -> Union[JoinedRoomsResponse, JoinedRoomsError]
        """Get the list of joined rooms.

        Returns either a `JoinedRoomsResponse` if the request was successful
        or a `JoinedRoomsError` if there was an error with the request.
        """
        method, path = Api.joined_rooms(
            self.access_token
        )

        return await self._send(
            JoinedRoomsResponse,
            method,
            path
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
    async def room_put_state(
            self,
            room_id:    str,
            event_type: str,
            content:    Dict[Any, Any],
            state_key:  str            = ""
    ) -> Union[RoomPutStateResponse, RoomPutStateError]:
        """Send a state event to a room.

        Returns either a `RoomPutStateResponse` if the request was successful
        or a `RoomPutStateError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room to send the event to.
            event_type (str): The type of the state to send.
            content (Dict[Any, Any]): The content of the event to be sent.
            state_key (str): The key of the state event to send.
        """

        method, path, data = Api.room_put_state(
            self.access_token,
            room_id,
            event_type,
            content,
            state_key = state_key
        )

        return await self._send(
            RoomPutStateResponse,
            method,
            path,
            data,
            response_data = (room_id,),
        )

    @logged_in
    async def room_get_state(
            self,
            room_id: str,
    ) -> Union[RoomGetStateResponse, RoomGetStateError]:
        """Fetch state for a room.

        Returns either a `RoomGetStateResponse` if the request was successful
        or a `RoomGetStateError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room to fetch state from.
        """

        method, path = Api.room_get_state(
            self.access_token,
            room_id,
        )

        return await self._send(
            RoomGetStateResponse,
            method,
            path,
            response_data = (room_id,),
        )

    @logged_in
    async def room_get_state_event(
            self,
            room_id:    str,
            event_type: str,
            state_key:  str  = ""
    ) -> Union[RoomGetStateEventResponse, RoomGetStateEventError]:
        """Fetch a state event from a room.

        Returns either a `RoomGetStateEventResponse` if the request was successful
        or a `RoomGetStateEventError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room to fetch the event from.
            event_type (str): The type of the state to fetch.
            state_key (str): The key of the state event to fetch.
        """

        method, path = Api.room_get_state_event(
            self.access_token,
            room_id,
            event_type,
            state_key = state_key
        )

        return await self._send(
            RoomGetStateEventResponse,
            method,
            path,
            response_data = (event_type, state_key, room_id,),
        )

    @logged_in
    async def room_redact(
            self,
            room_id:  str,
            event_id: str,
            reason:   Optional[str]          = None,
            tx_id:    Union[None, str, UUID] = None,
    ) -> Union[RoomRedactResponse, RoomRedactError]:
        """Strip information out of an event.

        Returns either a `RoomRedactResponse` if the request was successful or
        a `RoomRedactError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room that contains the event that
                will be redacted.
            event_id (str): The ID of the event that will be redacted.
            tx_id (str/UUID, optional): A transaction ID for this event.
            reason(str, optional): A description explaining why the
                event was redacted.
        """
        method, path, data = Api.room_redact(
            self.access_token,
            room_id,
            event_id,
            tx_id  = tx_id or uuid4(),
            reason = reason,
        )

        return await self._send(
            RoomRedactResponse,
            method,
            path,
            data,
            response_data = (room_id,),
        )

    async def room_resolve_alias(
            self,
            room_alias: str,
    ) -> Union[RoomResolveAliasResponse, RoomResolveAliasError]:
        """Resolve a room alias to a room ID.

        Returns either a `RoomResolveAliasResponse` if the request was
        successful or a `RoomResolveAliasError if there was an error
        with the request.

        Args:
            room_alias (str): The alias to resolve
        """
        method, path = Api.room_resolve_alias(room_alias)

        return await self._send(
            RoomResolveAliasResponse,
            method,
            path,
            response_data = (room_alias,),
        )

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

        Returns either a `RoomKeyRequestResponse` if the request was successful
        or a `RoomKeyRequestError` if there was an error with the request.

        Raises a LocalProtocolError if the room key was already requested.

        Args:
            event (MegolmEvent): An undecrypted MegolmEvent for which we would
                like to request the decryption key.
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

        Note that this does not save other information such as the private
        identity keys of the device.

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

    @logged_in
    async def room_create(
        self,
        visibility:           RoomVisibility           = RoomVisibility.private,
        alias:                Optional[str]            = None,
        name:                 Optional[str]            = None,
        topic:                Optional[str]            = None,
        room_version:         Optional[str]            = None,
        federate:             bool                     = True,
        is_direct:            bool                     = False,
        preset:               Optional[RoomPreset]     = None,
        invite:               Sequence[str]            = (),
        initial_state:        Sequence[Dict[str, Any]] = (),
        power_level_override: Optional[Dict[str, Any]] = None,
    ) -> Union[RoomCreateResponse, RoomCreateError]:
        """Create a new room.

        Returns either a `RoomCreateResponse` if the request was successful or
        a `RoomCreateError` if there was an error with the request.

        Args:
            visibility (RoomVisibility): whether to have the room published in
                the server's room directory or not.
                Defaults to ``RoomVisibility.Private``.

            alias (str, optional): The desired canonical alias local part.
                For example, if set to "foo" and the room is created on the
                "example.com" server, the room alias will be
                "#foo:example.com".

            name (str, optional): A name to set for the room.

            topic (str, optional): A topic to set for the room.

            room_version (str, optional): The room version to set.
                If not specified, the homeserver will use its default setting.
                If a version not supported by the homeserver is specified,
                a 400 ``M_UNSUPPORTED_ROOM_VERSION`` error will be returned.

            federate (bool): Whether to allow users from other homeservers from
                joining the room. Defaults to ``True``.
                Cannot be changed later.

            is_direct (bool): If this should be considered a
                direct messaging room.
                If ``True``, the server will set the ``is_direct`` flag on
                ``m.room.member events`` sent to the users in ``invite``.
                Defaults to ``False``.

            preset (RoomPreset, optional): The selected preset will set various
                rules for the room.
                If unspecified, the server will choose a preset from the
                ``visibility``: ``RoomVisibility.public`` equates to
                ``RoomPreset.public_chat``, and
                ``RoomVisibility.private`` equates to a
                ``RoomPreset.private_chat``.

            invite (list): A list of user id to invite to the room.

            initial_state (list): A list of state event dicts to send when
                the room is created.
                For example, a room could be made encrypted immediatly by
                having a ``m.room.encryption`` event dict.

            power_level_override (dict): A ``m.room.power_levels content`` dict
                to override the default.
                The dict will be applied on top of the generated
                ``m.room.power_levels`` event before it is sent to the room.
        """

        method, path, data = Api.room_create(
            self.access_token,
            visibility           = visibility,
            alias                = alias,
            name                 = name,
            topic                = topic,
            room_version         = room_version,
            federate             = federate,
            is_direct            = is_direct,
            preset               = preset,
            invite               = invite,
            initial_state        = initial_state,
            power_level_override = power_level_override,
        )

        return await self._send(RoomCreateResponse, method, path, data)

    @logged_in
    async def join(self, room_id):
        # type: (str) -> Union[JoinResponse, JoinError]
        """Join a room.

        This tells the server to join the given room.
        If the room is not public, the user must be invited.

        Returns either a `JoinResponse` if the request was successful or
        a `JoinError` if there was an error with the request.

        Args:
            room_id: The room id or alias of the room to join.
        """
        method, path, data = Api.join(self.access_token, room_id)
        return await self._send(JoinResponse, method, path, data)

    @logged_in
    async def room_invite(
        self, room_id: str, user_id: str,
    ) -> Union[RoomInviteResponse, RoomInviteError]:
        """Invite a user to a room.

        Returns either a `RoomInviteResponse` if the request was successful or
        a `RoomInviteError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room that the user will be
                invited to.
            user_id (str): The user id of the user that should be invited.
        """
        method, path, data = Api.room_invite(
            self.access_token, room_id, user_id,
        )
        return await self._send(RoomInviteResponse, method, path, data)

    @logged_in
    async def room_leave(self, room_id):
        # type: (str) -> Union[RoomLeaveResponse, RoomLeaveError]
        """Leave a room or reject an invite.

        This tells the server to leave the given room.
        If the user was only invited, the invite is rejected.

        Returns either a `RoomLeaveResponse` if the request was successful or
        a `RoomLeaveError` if there was an error with the request.

        Args:
            room_id: The room id of the room to leave.
        """
        method, path, data = Api.room_leave(self.access_token, room_id)
        return await self._send(RoomLeaveResponse, method, path, data)

    @logged_in
    async def room_forget(self, room_id):
        # type: (str) -> Union[RoomForgetResponse, RoomForgetError]
        """Forget a room.

        This tells the server to forget the given room's history for our user.
        If all users on a homeserver forget the room, the room will be
        eligible for deletion from that homeserver.

        Returns either a `RoomForgetResponse` if the request was successful or
        a `RoomForgetError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room to forget.
        """
        method, path, data = Api.room_forget(self.access_token, room_id)
        return await self._send(
            RoomForgetResponse,
            method,
            path,
            data,
            response_data=(room_id,)
        )

    @logged_in
    async def room_context(
            self,
            room_id,     # type: str
            event_id,    # type: str
            limit=None,  # type: Optional[int]
    ):
        # type: (...) -> Union[RoomContextResponse, RoomContextError]
        """Fetch a number of events that happened before and after an event.

        This allows clients to get the context surrounding an event.

        Returns either a `RoomContextResponse` if the request was successful or
        a `RoomContextError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room that contains the event and
                its context.
            event_id (str): The event_id of the event that we wish to get the
                context for.
            limit(int, optional): The maximum number of events to request.
        """

        method, path = Api.room_context(self.access_token, room_id, event_id,
                                        limit)

        return await self._send(RoomContextResponse, method, path,
                                response_data=(room_id, ))

    @logged_in
    async def room_messages(
            self,
            room_id,                          # type: str
            start,                            # type: str
            end=None,                         # type: Optional[str]
            direction=MessageDirection.back,  # type: MessageDirection
            limit=10                          # type: int
    ):
        # type: (...) -> Union[RoomMessagesResponse, RoomMessagesError]
        """Fetch a list of message and state events for a room.

        It uses pagination query parameters to paginate history in the room.

        Returns either a `RoomContextResponse` if the request was successful or
        a `RoomContextError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room for which we would like to
                fetch the messages.
            start (str): The token to start returning events from. This token
                can be obtained from a prev_batch token returned for each room
                by the sync API, or from a start or end token returned by a
                previous request to this endpoint.
            end (str, optional): The token to stop returning events at. This
                token can be obtained from a prev_batch token returned for
                each room by the sync endpoint, or from a start or end token
                returned by a previous request to this endpoint.
            direction (MessageDirection, optional): The direction to return
                events from. Defaults to MessageDirection.back.
            limit (int, optional): The maximum number of events to return.
                Defaults to 10.

        Example:
            >>> response = await client.room_messages(room_id, previous_batch)
            >>> next_response = await client.room_messages(room_id,
            ...                                            response.end)


        """
        method, path = Api.room_messages(
            self.access_token,
            room_id,
            start,
            end=end,
            direction=direction,
            limit=limit
        )

        return await self._send(
            RoomMessagesResponse,
            method,
            path,
            response_data=(room_id, )
        )

    @logged_in
    async def room_typing(
        self,
        room_id,            # type: str
        typing_state=True,  # type: bool
        timeout=30000       # type: int
    ):
        # type: (...) -> Union[RoomTypingResponse, RoomTypingError]
        """Send a typing notice to the server.

        This tells the server that the user is typing for the next N
        milliseconds or that the user has stopped typing.

        Returns either a `RoomTypingResponse` if the request was successful or
        a `RoomTypingError` if there was an error with the request.

        Args:
            room_id (str): The room id of the room where the user is typing.
            typing_state (bool): A flag representing whether the user started
                or stopped typing.
            timeout (int): For how long should the new typing notice be
                valid for in milliseconds.
        """
        method, path, data = Api.room_typing(
            self.access_token,
            room_id,
            self.user_id,
            typing_state,
            timeout
        )

        return await self._send(
            RoomTypingResponse,
            method,
            path,
            data,
            response_data=(room_id, )
        )

    @staticmethod
    async def _process_data_chunk(chunk, monitor=None):
        if monitor and monitor.cancel:
            raise TransferCancelledError()

        while monitor and monitor.pause:
            await asyncio.sleep(0.1)

        return chunk

    async def _plain_data_generator(self, data, monitor=None):
        """Yield chunks of bytes from data.

        If a monitor is passed, update its ``transferred`` property and
        suspend yielding chunks while its ``pause`` attribute is ``True``.

        Raise ``TransferCancelledError`` if ``monitor.cancel`` is ``True``.
        """

        async for value in async_generator_from_data(data):
            yield await self._process_data_chunk(value, monitor)

    async def _encrypted_data_generator(
        self, data, decryption_dict, monitor=None,
    ):
        """Yield encrypted chunks of bytes from data.

        If a monitor is passed, update its ``transferred`` property and
        suspend yielding chunks while its ``pause`` attribute is ``True``.

        The last yielded value will be the decryption dict.

        Raise ``TransferCancelledError`` if ``monitor.cancel`` is ``True``.
        """

        async for value in async_encrypt_attachment(data):
            if isinstance(value, dict):  # last yielded value
                decryption_dict.update(value)
            else:
                yield await self._process_data_chunk(value, monitor)

    @logged_in
    async def upload(
        self,
        data_provider: DataProvider,
        content_type:  str                       = "application/octet-stream",
        filename:      Optional[str]             = None,
        encrypt:       bool                      = False,
        monitor:       Optional[TransferMonitor] = None,
    ) -> Tuple[Union[UploadResponse, UploadError], Optional[Dict[str, Any]]]:
        # TODO: test retries
        """Upload a file to the content repository.

        Returns a tuple containing:

        - Either a `UploadResponse` if the request was successful, or a
          `UploadError` if there was an error with the request

        - A dict with file decryption info if encrypt is ``True``,
          else ``None``.

        Raises a ``TransferCancelledError`` if a monitor is passed and its
        ``cancelled`` property becomes set to ``True``.

        Args:
            data_provider (Callable): A function returning the data to upload.
                Returning a path string, Path, async iterable or aiofiles open
                binary file object allows the file data to be read in an
                asynchronous and lazy (without reading the entire file into
                memory) way.
                Returning a non-async iterable or standard open binary file
                object will still allow the data to be read lazily, but
                not asynchronously.

                The function will be called again if the upload fails
                due to a server timeout, in which case it must restart
                from the beginning.
                The function receives two arguments: the total number of
                429 "Too many request" errors that occured, and the total
                number of server timeout exceptions that occured, thus
                cleanup operations can be performed for retries if necessary.

            content_type (str): The content MIME type of the file,
                e.g. "image/png".
                Defaults to "application/octet-stream", corresponding to a
                generic binary file.
                Custom values are ignored if encrypt is ``True``.

            filename (str, optional): The file's original name.

            encrypt (bool): If the file's content should be encrypted,
                necessary for files that will be sent to encrypted rooms.
                Defaults to ``False``.

            monitor (TransferMonitor, optional): If a ``TransferMonitor``
                object is passed, it will be updated by this function while
                uploading.
                From this object, statistics such as currently
                transferred bytes or estimated remaining time can be gathered
                while the upload is running as a task; it also allows
                for pausing and cancelling.
        """

        http_method, path, _ = Api.upload(self.access_token, filename)

        decryption_dict: Dict[str, Any] = {}

        def provider(got_429, got_timeouts):
            if monitor and (got_429 or got_timeouts):
                # We have to restart from scratch
                monitor.transferred = 0

            data = data_provider(got_429, got_timeouts)

            if encrypt:
                return self._encrypted_data_generator(
                    data, decryption_dict, monitor,
                )

            return self._plain_data_generator(data, monitor)

        response = await self._send(
            UploadResponse,
            http_method,
            path,
            data_provider = provider,
            content_type  =
                "application/octet-stream" if encrypt else content_type,
            trace_context = monitor,
        )

        # After the upload finished and we get the response above, if encrypt
        # is True, decryption_dict will have been updated from inside the
        # self._encrypted_data_generator().
        return (response, decryption_dict if encrypt else None)

    @client_session
    async def download(
        self,
        server_name:  str,
        media_id:     str,
        filename:     Optional[str]             = None,
        allow_remote: bool                      = True,
    ):
        # type: (...) -> Union[DownloadResponse, DownloadError]
        """Get the content of a file from the content repository.

        Returns either a `DownloadResponse` if the request was successful or
        a `DownloadError` if there was an error with the request.

        Args:
            server_name (str): The server name from the mxc:// URI.
            media_id (str): The media ID from the mxc:// URI.
            filename (str, optional): A filename to be returned in the response
                by the server. If None (default), the original name of the
                file will be returned instead, if there is one.
            allow_remote (bool): Indicates to the server that it should not
                attempt to fetch the media if it is deemed remote.
                This is to prevent routing loops where the server contacts
                itself.
        """
        # TODO: support TransferMonitor

        http_method, path = Api.download(
            server_name,
            media_id,
            filename,
            allow_remote
        )

        return await self._send(DownloadResponse, http_method, path)


    @client_session
    async def thumbnail(
        self,
        server_name,                  # type: str
        media_id,                     # type: str
        width,                        # type: int
        height,                       # type: int
        method=ResizingMethod.scale,  # ŧype: ResizingMethod
        allow_remote=True,            # type: bool
    ):
        # type: (...) -> Union[ThumbnailResponse, ThumbnailError]
        """Get the thumbnail of a file from the content repository.

        Note: The actual thumbnail may be larger than the size specified.

        Returns either a `ThumbnailResponse` if the request was successful or
        a `ThumbnailError` if there was an error with the request.

        Args:
            server_name (str): The server name from the mxc:// URI.
            media_id (str): The media ID from the mxc:// URI.
            width (int): The desired width of the thumbnail.
            height (int): The desired height of the thumbnail.
            method (ResizingMethod): The desired resizing method.
            allow_remote (bool): Indicates to the server that it should not
                attempt to fetch the media if it is deemed remote.
                This is to prevent routing loops where the server contacts
                itself.
        """
        http_method, path = Api.thumbnail(
            server_name,
            media_id,
            width,
            height,
            method,
            allow_remote
        )

        return await self._send(ThumbnailResponse, http_method, path)

    @client_session
    async def get_profile(self, user_id=None):
        # type: (Optional[str]) -> Union[ProfileGetResponse, ProfileGetError]
        """Get a user's combined profile information.

        This queries the display name and avatar matrix content URI of a user
        from the server. Additional profile information may be present.
        The currently logged in user is queried if no user is specified.

        Returns either a `ProfileGetResponse` if the request was
        successful or a `ProfileGetError` if there was an error
        with the request.

        Args:
            user_id (str): User id of the user to get the profile for.
        """
        method, path = Api.profile_get(user_id or self.user_id)

        return await self._send(
            ProfileGetResponse,
            method,
            path,
        )

    @client_session
    async def get_displayname(
            self,
            user_id=None  # type: Optional[str]
    ):
        # type: (...) -> _ProfileGetDisplayNameT
        """Get a user's display name.

        This queries the display name of a user from the server.
        The currently logged in user is queried if no user is specified.

        Returns either a `ProfileGetDisplayNameResponse` if the request was
        successful or a `ProfileGetDisplayNameError` if there was an error
        with the request.

        Args:
            user_id (str): User id of the user to get the display name for.
        """
        method, path = Api.profile_get_displayname(user_id or self.user_id)

        return await self._send(
            ProfileGetDisplayNameResponse,
            method,
            path,
        )

    @logged_in
    async def set_displayname(self, displayname):
        # type: (str) -> _ProfileSetDisplayNameT
        """Set user's display name.

        This tells the server to set display name of the currently logged
        in user to the supplied string.

        Returns either a `ProfileSetDisplayNameResponse` if the request was
        successful or a `ProfileSetDisplayNameError` if there was an error
        with the request.

        Args:
            displayname (str): Display name to set.
        """
        method, path, data = Api.profile_set_displayname(
            self.access_token,
            self.user_id,
            displayname
        )

        return await self._send(
            ProfileSetDisplayNameResponse,
            method,
            path,
            data,
        )

    @client_session
    async def get_avatar(
            self,
            user_id=None  # type: Optional[str]
    ):
        # type: (...) -> Union[ProfileGetAvatarResponse, ProfileGetAvatarError]
        """Get a user's avatar URL.

        This queries the avatar matrix content URI of a user from the server.
        The currently logged in user is queried if no user is specified.

        Returns either a `ProfileGetAvatarResponse` if the request was
        successful or a `ProfileGetAvatarError` if there was an error
        with the request.

        Args:
            user_id (str): User id of the user to get the avatar for.
        """
        method, path = Api.profile_get_avatar(user_id or self.user_id)

        return await self._send(
            ProfileGetAvatarResponse,
            method,
            path,
        )

    @logged_in
    async def set_avatar(self, avatar_url):
        # type: (str) -> Union[ProfileSetAvatarResponse, ProfileSetAvatarError]
        """Set the user's avatar URL.

        This tells the server to set the avatar of the currently logged
        in user to supplied matrix content URI.

        Returns either a `ProfileSetAvatarResponse` if the request was
        successful or a `ProfileSetAvatarError` if there was an error
        with the request.

        Args:
            avatar_url (str): matrix content URI of the avatar to set.
        """
        method, path, data = Api.profile_set_avatar(
            self.access_token,
            self.user_id,
            avatar_url
        )

        return await self._send(
            ProfileSetAvatarResponse,
            method,
            path,
            data,
        )
