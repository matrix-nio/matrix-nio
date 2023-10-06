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

from __future__ import annotations

import json
import logging
import pprint
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage
from functools import wraps
from typing import Any, Deque, Dict, List, Optional, Tuple, Type, Union
from urllib.parse import urlparse
from uuid import UUID, uuid4

import h2
import h11

from ..api import Api, MessageDirection, ResizingMethod, RoomPreset, RoomVisibility
from ..crypto import OlmDevice
from ..event_builders import ToDeviceMessage
from ..events import MegolmEvent
from ..exceptions import LocalProtocolError, RemoteTransportError
from ..http import (
    Http2Connection,
    Http2Request,
    HttpConnection,
    HttpRequest,
    TransportRequest,
    TransportResponse,
    TransportType,
)
from ..responses import (
    DeleteDevicesAuthResponse,
    DeleteDevicesResponse,
    DevicesResponse,
    DownloadResponse,
    FileResponse,
    JoinedMembersResponse,
    JoinResponse,
    KeysClaimResponse,
    KeysQueryResponse,
    KeysUploadError,
    KeysUploadResponse,
    LoginInfoResponse,
    LoginResponse,
    LogoutResponse,
    ProfileGetAvatarResponse,
    ProfileGetDisplayNameResponse,
    ProfileGetResponse,
    ProfileSetAvatarResponse,
    ProfileSetDisplayNameResponse,
    Response,
    RoomCreateResponse,
    RoomForgetResponse,
    RoomInviteResponse,
    RoomKeyRequestResponse,
    RoomKickResponse,
    RoomLeaveResponse,
    RoomMessagesResponse,
    RoomPutStateResponse,
    RoomReadMarkersResponse,
    RoomRedactResponse,
    RoomSendResponse,
    RoomTypingResponse,
    ShareGroupSessionResponse,
    SyncResponse,
    ThumbnailResponse,
    ToDeviceResponse,
    UpdateDeviceResponse,
)
from . import Client, ClientConfig
from .base_client import logged_in, store_loaded

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError  # type: ignore


logger = logging.getLogger(__name__)


def connected(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self.connection:
            raise LocalProtocolError("Not connected.")
        return func(self, *args, **kwargs)

    return wrapper


@dataclass
class RequestInfo:
    request_class: Type[Response] = field()
    extra_data: Tuple = ()


class HttpClient(Client):
    def __init__(
        self,
        homeserver: str,
        user: str = "",
        device_id: Optional[str] = "",
        store_path: Optional[str] = "",
        config: Optional[ClientConfig] = None,
    ) -> None:
        self.host, self.extra_path = HttpClient._parse_homeserver(homeserver)
        self.requests_made: Dict[UUID, RequestInfo] = {}
        self.parse_queue: Deque[Tuple[RequestInfo, TransportResponse]] = deque()

        self.connection: Optional[Union[HttpConnection, Http2Connection]] = None

        super().__init__(user, device_id, store_path, config)

    @staticmethod
    def _parse_homeserver(homeserver):
        if not homeserver.startswith("http"):
            homeserver = f"https://{homeserver}"

        homeserver = urlparse(homeserver)

        if homeserver.port:
            port = homeserver.port
        else:
            if homeserver.scheme == "https":
                port = 443
            elif homeserver.scheme == "http":
                port = 80
            else:
                raise ValueError("Invalid URI scheme for Homeserver")

        host = f"{homeserver.hostname}:{port}"
        extra_path = homeserver.path.strip("/")

        return host, extra_path

    @connected
    def _send(
        self,
        request: TransportRequest,
        request_info: RequestInfo,
        uuid: Optional[UUID] = None,
    ) -> Tuple[UUID, bytes]:
        assert self.connection

        ret_uuid, data = self.connection.send(request, uuid)
        self.requests_made[ret_uuid] = request_info
        return ret_uuid, data

    def _add_extra_path(self, path):
        if self.extra_path:
            return f"/{self.extra_path}{path}"
        return path

    def _build_request(self, api_response, timeout=0):
        def unpack_api_call(method, *rest):
            return method, rest

        method, api_data = unpack_api_call(*api_response)

        if isinstance(self.connection, HttpConnection):
            if method == "GET":
                path = self._add_extra_path(api_data[0])
                return HttpRequest.get(self.host, path, timeout)
            elif method == "POST":
                path, data = api_data
                path = self._add_extra_path(path)
                return HttpRequest.post(self.host, path, data, timeout)
            elif method == "PUT":
                path, data = api_data
                path = self._add_extra_path(path)
                return HttpRequest.put(self.host, path, data, timeout)
        elif isinstance(self.connection, Http2Connection):
            if method == "GET":
                path = api_data[0]
                path = self._add_extra_path(path)
                return Http2Request.get(self.host, path, timeout)
            elif method == "POST":
                path, data = api_data
                path = self._add_extra_path(path)
                return Http2Request.post(self.host, path, data, timeout)
            elif method == "PUT":
                path, data = api_data
                path = self._add_extra_path(path)
                return Http2Request.put(self.host, path, data, timeout)

        assert "Invalid connection type"

    @property
    def lag(self) -> float:
        if not self.connection:
            return 0

        return self.connection.elapsed

    def connect(
        self, transport_type: Optional[TransportType] = TransportType.HTTP
    ) -> bytes:
        if transport_type == TransportType.HTTP:
            self.connection = HttpConnection()
        elif transport_type == TransportType.HTTP2:
            self.connection = Http2Connection()
        else:
            raise NotImplementedError

        return self.connection.connect()

    def _clear_queues(self):
        self.requests_made.clear()
        self.parse_queue.clear()

    @connected
    def disconnect(self) -> bytes:
        assert self.connection

        data = self.connection.disconnect()
        self._clear_queues()
        self.connection = None
        return data

    @connected
    def data_to_send(self) -> bytes:
        assert self.connection
        return self.connection.data_to_send()

    @connected
    def login_info(self) -> Tuple[UUID, bytes]:
        """Get the available login methods from the server

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        """
        request = self._build_request(Api.login_info())

        return self._send(request, RequestInfo(LoginInfoResponse))

    @connected
    def login(
        self,
        password: Optional[str] = None,
        device_name: Optional[str] = "",
        token: Optional[str] = None,
    ) -> Tuple[UUID, bytes]:
        if password is None and token is None:
            raise ValueError("Either a password or a token needs to be " "provided")

        request = self._build_request(
            Api.login(
                self.user,
                password=password,
                device_name=device_name,
                device_id=self.device_id,
                token=token,
            )
        )

        return self._send(request, RequestInfo(LoginResponse))

    @connected
    def login_raw(self, auth_dict: Dict[str, Any]) -> Tuple[UUID, bytes]:
        if auth_dict is None or auth_dict == {}:
            raise ValueError("Auth dictionary shall not be empty")

        request = self._build_request(Api.login_raw(auth_dict))

        return self._send(request, RequestInfo(LoginResponse))

    @connected
    @logged_in
    def logout(self, all_devices=False):
        request = self._build_request(Api.logout(self.access_token, all_devices))

        return self.send(request, RequestInfo(LogoutResponse))

    @connected
    @logged_in
    def room_send(self, room_id, message_type, content, tx_id=None):
        if self.olm:
            try:
                room = self.rooms[room_id]
            except KeyError:
                raise LocalProtocolError(f"No such room with id {room_id} found.")

            if room.encrypted:
                message_type, content = self.encrypt(
                    room_id,
                    message_type,
                    content,
                )

        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.room_send(self.access_token, room_id, message_type, content, uuid)
        )

        return self._send(request, RequestInfo(RoomSendResponse, (room_id,)), uuid)

    @connected
    @logged_in
    def room_put_state(self, room_id, event_type, body):
        request = self._build_request(
            Api.room_put_state(self.access_token, room_id, event_type, body)
        )

        return self._send(request, RequestInfo(RoomPutStateResponse, (room_id,)))

    @connected
    @logged_in
    def room_redact(self, room_id, event_id, reason=None, tx_id=None):
        """Strip information out of an event.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            room_id (str): The room id of the room that contains the event that
                will be redacted.
            event_id (str): The ID of the event that will be redacted.
            tx_id (str/UUID, optional): A transaction ID for this event.
            reason(str, optional): A description explaining why the
                event was redacted.
        """
        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.room_redact(
                self.access_token,
                room_id,
                event_id,
                tx_id,
                reason=reason,
            )
        )

        return self._send(request, RequestInfo(RoomRedactResponse, (room_id,)), uuid)

    @connected
    @logged_in
    def room_kick(self, room_id, user_id, reason=None):
        request = self._build_request(
            Api.room_kick(self.access_token, room_id, user_id, reason=reason)
        )

        return self._send(request, RequestInfo(RoomKickResponse))

    @connected
    @logged_in
    def room_invite(self, room_id, user_id):
        request = self._build_request(
            Api.room_invite(self.access_token, room_id, user_id)
        )

        return self._send(request, RequestInfo(RoomInviteResponse))

    @connected
    @logged_in
    def room_create(
        self,
        visibility: RoomVisibility = RoomVisibility.private,
        alias: Optional[str] = None,
        name: Optional[str] = None,
        topic: Optional[str] = None,
        room_version: Optional[str] = None,
        room_type: Optional[str] = None,
        federate: bool = True,
        is_direct: bool = False,
        preset: Optional[RoomPreset] = None,
        invite: Sequence[str] = (),
        initial_state: Sequence[Dict[str, Any]] = (),
        power_level_override: Optional[Dict[str, Any]] = None,
    ) -> Tuple[UUID, bytes]:
        """Create a new room.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            visibility (RoomVisibility): whether to have the room published in
                the server's room directory or not.
                Defaults to ``RoomVisibility.private``.

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

            room_type (str, optional): The room type to set.
                If not specified, the homeserver will use its default setting.
                In spec v1.2 the following room types are specified:
                    - ``m.space``
                Unspecified room types are permitted through the use of Namespaced Identifiers.

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
                For example, a room could be made encrypted immediately by
                having a ``m.room.encryption`` event dict.

            power_level_override (dict): A ``m.room.power_levels content`` dict
                to override the default.
                The dict will be applied on top of the generated
                ``m.room.power_levels`` event before it is sent to the room.
        """

        request = self._build_request(
            Api.room_create(
                self.access_token,
                visibility=visibility,
                alias=alias,
                name=name,
                topic=topic,
                room_version=room_version,
                room_type=room_type,
                federate=federate,
                is_direct=is_direct,
                preset=preset,
                invite=invite,
                initial_state=initial_state,
                power_level_override=power_level_override,
            )
        )

        return self._send(request, RequestInfo(RoomCreateResponse))

    @connected
    @logged_in
    def join(self, room_id: str) -> Tuple[UUID, bytes]:
        """Join a room.

        This tells the server to join the given room.
        If the room is not public, the user must be invited.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            room_id: The room id or alias of the room to join.
        """
        request = self._build_request(Api.join(self.access_token, room_id))
        return self._send(request, RequestInfo(JoinResponse))

    @connected
    @logged_in
    def room_leave(self, room_id: str) -> Tuple[UUID, bytes]:
        """Leave a room or reject an invite.

        This tells the server to leave the given room.
        If the user was only invited, the invite is rejected.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            room_id: The room id of the room to leave.
        """
        request = self._build_request(Api.room_leave(self.access_token, room_id))
        return self._send(request, RequestInfo(RoomLeaveResponse))

    @connected
    @logged_in
    def room_forget(self, room_id: str) -> Tuple[UUID, bytes]:
        """Forget a room.

        This tells the server to forget the given room's history for our user.
        If all users on a homeserver forget the room, the room will be
        eligible for deletion from that homeserver.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            room_id (str): The room id of the room to forget.
        """
        request = self._build_request(Api.room_forget(self.access_token, room_id))
        return self._send(request, RequestInfo(RoomForgetResponse, (room_id,)))

    @connected
    @logged_in
    def room_messages(
        self, room_id, start, end=None, direction=MessageDirection.back, limit=10
    ):
        request = self._build_request(
            Api.room_messages(
                self.access_token,
                room_id,
                start,
                end=end,
                direction=direction,
                limit=limit,
            )
        )
        return self._send(request, RequestInfo(RoomMessagesResponse, (room_id,)))

    @connected
    @logged_in
    def room_typing(
        self,
        room_id: str,
        typing_state: bool = True,
        timeout: int = 30000,
    ) -> Tuple[UUID, bytes]:
        """Send a typing notice to the server.

        This tells the server that the user is typing for the next N
        milliseconds or that the user has stopped typing.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            room_id (str): Room id of the room where the user is typing.
            typing_state (bool): A flag representing whether the user started
                or stopped typing
            timeout (int): For how long should the new typing notice be
                valid for in milliseconds.
        """
        request = self._build_request(
            Api.room_typing(
                self.access_token, room_id, self.user_id, typing_state, timeout
            )
        )
        return self._send(request, RequestInfo(RoomTypingResponse, (room_id,)))

    @connected
    @logged_in
    def room_read_markers(
        self,
        room_id: str,
        fully_read_event: str,
        read_event: Optional[str] = None,
    ) -> Tuple[UUID, bytes]:
        """Update the fully read marker (and optionally the read receipt) for
        a room.

        Calls receive_response() to update the client state if necessary.

        Returns either a `RoomReadMarkersResponse` if the request was
        successful or a `RoomReadMarkersError` if there was an error with
        the request.

        This sets the position of the read markers.

        - `fully_read_event` is the latest event in the set of events that the
          user has either fully read or indicated they aren't interested in. It
          permits the implementation of a "jump to first unread message" kind
          of feature. It is _private_ (not exposed to other room participants).

        - `read_event` is the most recent message the user has read and is also
          known as a _read receipt_. A read receipt being set on an event does
          not imply that all previous events have been seen. This happens in
          cases such as when a user comes back to a room after hundreds of
          messages have been sent and _only_ reads the most recent message. The
          read receipt is _public_ (exposed to other room participants).

        If you want to set the read receipt, you _must_ set `read_event`.

        Args:
            room_id (str): The room ID of the room where the read markers should
                be updated.
            fully_read_event (str): The event ID that the user has fully read up
                to.
            read_event (Optional[str]): The event ID to set the read receipt
                location at.
        """
        request = self._build_request(
            Api.room_read_markers(
                self.access_token, room_id, fully_read_event, read_event
            )
        )
        return self._send(request, RequestInfo(RoomReadMarkersResponse, (room_id,)))

    @connected
    def download(
        self,
        server_name: str,
        media_id: str,
        filename: Optional[str] = None,
        allow_remote: bool = True,
    ) -> Tuple[UUID, bytes]:
        """Get the content of a file from the content repository.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

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
        request = self._build_request(
            Api.download(server_name, media_id, filename, allow_remote)
        )

        return self._send(request, RequestInfo(DownloadResponse))

    @connected
    def thumbnail(
        self,
        server_name: str,
        media_id: str,
        width: int,
        height: int,
        method=ResizingMethod.scale,  # ŧype: ResizingMethod
        allow_remote: bool = True,
    ) -> Tuple[UUID, bytes]:
        """Get the thumbnail of a file from the content repository.

        Note: The actual thumbnail may be larger than the size specified.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

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
        request = self._build_request(
            Api.thumbnail(server_name, media_id, width, height, method, allow_remote)
        )

        return self._send(request, RequestInfo(ThumbnailResponse))

    @connected
    @logged_in
    @store_loaded
    def keys_upload(self):
        keys_dict = self.olm.share_keys()

        logger.debug(pprint.pformat(keys_dict))

        request = self._build_request(Api.keys_upload(self.access_token, keys_dict))
        return self._send(request, RequestInfo(KeysUploadResponse))

    @connected
    @logged_in
    @store_loaded
    def keys_query(self):
        """Query the server for user keys.

        This queries the server for device keys of users with which we share an
        encrypted room.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.
        """
        user_list = self.users_for_key_query

        if not user_list:
            raise LocalProtocolError("No key query required.")

        request = self._build_request(Api.keys_query(self.access_token, user_list))
        return self._send(request, RequestInfo(KeysQueryResponse))

    @connected
    @logged_in
    @store_loaded
    def keys_claim(self, room_id):
        user_list = self.get_missing_sessions(room_id)

        request = self._build_request(Api.keys_claim(self.access_token, user_list))
        return self._send(request, RequestInfo(KeysClaimResponse, (room_id,)))

    @connected
    @logged_in
    @store_loaded
    def share_group_session(
        self,
        room_id: str,
        ignore_missing_sessions: bool = False,
        tx_id: Optional[str] = None,
        ignore_unverified_devices: bool = False,
    ) -> Tuple[UUID, bytes]:
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
        store isn't loaded, no room with the given room id exists or the room
        isn't an encrypted room.
        """

        assert self.olm
        try:
            room = self.rooms[room_id]
        except KeyError:
            raise LocalProtocolError(f"No such room with id {room_id}")

        if not room.encrypted:
            raise LocalProtocolError(f"Room with id {room_id} is not encrypted")

        user_map, to_device_dict = self.olm.share_group_session(
            room_id,
            list(room.users.keys()),
            ignore_missing_sessions,
            ignore_unverified_devices,
        )

        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.to_device(self.access_token, "m.room.encrypted", to_device_dict, uuid)
        )

        return self._send(
            request, RequestInfo(ShareGroupSessionResponse, (room_id, user_map))
        )

    @connected
    @logged_in
    def devices(self) -> Tuple[UUID, bytes]:
        request = self._build_request(Api.devices(self.access_token))
        return self._send(request, RequestInfo(DevicesResponse))

    @connected
    @logged_in
    def update_device(
        self, device_id: str, content: Dict[str, str]
    ) -> Tuple[UUID, bytes]:
        request = self._build_request(
            Api.update_device(self.access_token, device_id, content)
        )

        return self._send(request, RequestInfo(UpdateDeviceResponse))

    @connected
    @logged_in
    def delete_devices(
        self, devices: List[str], auth: Optional[Dict[str, str]] = None
    ) -> Tuple[UUID, bytes]:
        request = self._build_request(
            Api.delete_devices(self.access_token, devices, auth_dict=auth)
        )

        return self._send(request, RequestInfo(DeleteDevicesResponse))

    @connected
    @logged_in
    def joined_members(self, room_id: str) -> Tuple[UUID, bytes]:
        request = self._build_request(Api.joined_members(self.access_token, room_id))

        return self._send(request, RequestInfo(JoinedMembersResponse, (room_id,)))

    @connected
    def get_profile(self, user_id: Optional[str] = None) -> Tuple[UUID, bytes]:
        """Get a user's combined profile information.

        This queries the display name and avatar matrix content URI of a user
        from the server. Additional profile information may be present.
        The currently logged in user is queried if no user is specified.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            user_id (str): User id of the user to get the profile for.
        """
        request = self._build_request(
            Api.profile_get(
                user_id or self.user_id, access_token=self.access_token or None
            )
        )

        return self._send(request, RequestInfo(ProfileGetResponse))

    @connected
    def get_displayname(self, user_id: Optional[str] = None) -> Tuple[UUID, bytes]:
        """Get a user's display name.

        This queries the display name of a user from the server.
        The currently logged in user is queried if no user is specified.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            user_id (str): User id of the user to get the display name for.
        """
        request = self._build_request(
            Api.profile_get_displayname(
                user_id or self.user_id, access_token=self.access_token or None
            )
        )

        return self._send(request, RequestInfo(ProfileGetDisplayNameResponse))

    @connected
    @logged_in
    def set_displayname(self, displayname: str) -> Tuple[UUID, bytes]:
        """Set the user's display name.

        This tells the server to set the display name of the currently logged
        in user to supplied string.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            displayname (str): Display name to set.
        """
        request = self._build_request(
            Api.profile_set_displayname(self.access_token, self.user_id, displayname)
        )
        return self._send(request, RequestInfo(ProfileSetDisplayNameResponse))

    @connected
    def get_avatar(self, user_id: Optional[str] = None) -> Tuple[UUID, bytes]:
        """Get a user's avatar URL.

        This queries the avatar matrix content URI of a user from the server.
        The currently logged in user is queried if no user is specified.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            user_id (str): User id of the user to get the avatar for.
        """
        request = self._build_request(
            Api.profile_get_avatar(
                user_id or self.user_id, access_token=self.access_token or None
            )
        )

        return self._send(request, RequestInfo(ProfileGetAvatarResponse))

    @connected
    @logged_in
    def set_avatar(self, avatar_url: str) -> Tuple[UUID, bytes]:
        """Set the user's avatar URL.

        This tells the server to set avatar of the currently logged
        in user to supplied matrix content URI.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            avatar_url (str): matrix content URI of the avatar to set.
        """
        request = self._build_request(
            Api.profile_set_avatar(self.access_token, self.user_id, avatar_url)
        )
        return self._send(request, RequestInfo(ProfileSetAvatarResponse))

    @connected
    @logged_in
    @store_loaded
    def request_room_key(
        self, event: MegolmEvent, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Request a missing room key.

        This sends out a message to other devices requesting a room key from
        them.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            event (str): An undecrypted MegolmEvent for which we would like to
                request the decryption key.
        """
        uuid = tx_id or uuid4()

        if event.session_id in self.outgoing_key_requests:
            raise LocalProtocolError(
                "A key sharing request is already sent" " out for this session id."
            )

        assert self.user_id
        assert self.device_id

        message = event.as_key_request(self.user_id, self.device_id)

        request = self._build_request(
            Api.to_device(self.access_token, message.type, message.as_dict(), uuid)
        )
        return self._send(
            request,
            RequestInfo(
                RoomKeyRequestResponse,
                (event.session_id, event.session_id, event.room_id, event.algorithm),
            ),
        )

    @connected
    @logged_in
    @store_loaded
    def confirm_short_auth_string(
        self, transaction_id: str, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Confirm a short auth string and mark it as matching.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
        """
        message = self.confirm_key_verification(transaction_id)
        return self.to_device(message)

    @connected
    @logged_in
    @store_loaded
    def start_key_verification(
        self, device: OlmDevice, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Start a interactive key verification with the given device.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            device (OlmDevice): An device with which we would like to start the
                interactive key verification process.
        """
        message = self.create_key_verification(device)
        return self.to_device(message, tx_id)

    @connected
    @logged_in
    @store_loaded
    def accept_key_verification(
        self, transaction_id: str, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Accept a key verification start event.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
        """
        if transaction_id not in self.key_verifications:
            raise LocalProtocolError(
                f"Key verification with the transaction id {transaction_id} does not exist."
            )

        sas = self.key_verifications[transaction_id]

        message = sas.accept_verification()

        return self.to_device(message, tx_id)

    @connected
    @logged_in
    @store_loaded
    def cancel_key_verification(
        self, transaction_id: str, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Abort an interactive key verification.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            transaction_id (str): An transaction id of a valid key verification
                process.
        """
        if transaction_id not in self.key_verifications:
            raise LocalProtocolError(
                f"Key verification with the transaction id {transaction_id} does not exist."
            )

        sas = self.key_verifications[transaction_id]
        sas.cancel()

        message = sas.get_cancellation()

        return self.to_device(message, tx_id)

    @logged_in
    @store_loaded
    def to_device(
        self, message: ToDeviceMessage, tx_id: Optional[str] = None
    ) -> Tuple[UUID, bytes]:
        """Send a message to a specific device.

        Returns a unique uuid that identifies the request and the bytes that
        should be sent to the socket.

        Args:
            message (ToDeviceMessage): The message that should be sent out.
            tx_id (str, optional): The transaction ID for this message. Should
                be unique.
        """
        uuid = tx_id or uuid4()

        request = self._build_request(
            Api.to_device(self.access_token, message.type, message.as_dict(), uuid)
        )
        return self._send(request, RequestInfo(ToDeviceResponse, (message,)))

    @connected
    @logged_in
    def sync(
        self,
        timeout: Optional[int] = None,
        filter: Optional[Dict[Any, Any]] = None,
        full_state: bool = False,
    ) -> Tuple[UUID, bytes]:
        request = self._build_request(
            Api.sync(
                self.access_token,
                since=self.next_batch or self.loaded_sync_token,
                timeout=timeout,
                filter=filter,
                full_state=full_state,
            ),
            timeout,
        )

        return self._send(request, RequestInfo(SyncResponse))

    def parse_body(self, transport_response: TransportResponse) -> Dict[Any, Any]:
        """Parse the body of the response.

        Args:
            transport_response(TransportResponse): The transport response that
                contains the body of the response.

        Returns a dictionary representing the response.
        """
        try:
            return json.loads(transport_response.text)
        except JSONDecodeError:
            return {}

    def _create_response(self, request_info, transport_response, max_events=0):
        request_class = request_info.request_class
        extra_data = request_info.extra_data or ()

        try:
            content_type = str(transport_response.headers[b"content-type"], "utf-8")
        except KeyError:
            content_type = None

        try:
            disposition = str(
                transport_response.headers[b"content-disposition"], "utf-8"
            )
            message = EmailMessage()
            message["Content-Disposition"] = disposition
            filename = message.get_filename()
        except KeyError:
            filename = None

        is_json = content_type == "application/json"

        if issubclass(request_class, FileResponse) and is_json:
            parsed_dict = self.parse_body(transport_response)
            response = request_class.from_data(
                parsed_dict, content_type, filename, *extra_data
            )

        elif issubclass(request_class, FileResponse):
            body = transport_response.content
            response = request_class.from_data(
                body, content_type, filename, *extra_data
            )

        else:
            parsed_dict = self.parse_body(transport_response)

            if (
                transport_response.status_code == 401
                and request_class == DeleteDevicesResponse
            ):
                response = DeleteDevicesAuthResponse.from_dict(parsed_dict)

            response = request_class.from_dict(parsed_dict, *extra_data)

        assert response

        logger.info(f"Received new response of type {response.__class__.__name__}")

        response.start_time = transport_response.send_time
        response.end_time = transport_response.receive_time
        response.timeout = transport_response.timeout
        response.status_code = transport_response.status_code
        response.uuid = transport_response.uuid

        return response

    def handle_key_upload_error(self, response):
        if not self.olm:
            return

        if response.status_code in [400, 500]:
            self.olm.mark_keys_as_published()
            self.olm.save_account()

    @connected
    def receive(self, data: bytes) -> None:
        """Pass received data to the client"""
        assert self.connection

        try:
            response = self.connection.receive(data)
        except (h11.RemoteProtocolError, h2.exceptions.ProtocolError) as e:
            raise RemoteTransportError(e)

        if response:
            try:
                request_info = self.requests_made.pop(response.uuid)
            except KeyError:
                logger.error(f"{pprint.pformat(self.requests_made)}")
                raise

            if response.is_ok:
                logger.info(f"Received response of type: {request_info.request_class}")
            else:
                logger.info(
                    "Error with response of type type: {}, error code {}".format(
                        request_info.request_class, response.status_code
                    )
                )

            self.parse_queue.append((request_info, response))
        return

    def next_response(
        self, max_events: int = 0
    ) -> Optional[Union[TransportResponse, Response]]:
        if not self.parse_queue:
            return None

        request_info, transport_response = self.parse_queue.popleft()
        response = self._create_response(request_info, transport_response, max_events)

        if isinstance(response, KeysUploadError):
            self.handle_key_upload_error(response)

        self.receive_response(response)

        return response
