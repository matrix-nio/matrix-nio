# -*- coding: utf-8 -*-

# Copyright © 2018 Damir Jelić <poljar@termina.org.uk>
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

"""nio api module.

This module contains primitives to build Matrix API http requests.
"""


from __future__ import unicode_literals

import json
from collections import defaultdict
from enum import Enum, unique
from typing import (Any, DefaultDict, Dict, Iterable, List,
                    Optional, Set, Sequence, Tuple, Union)

from .exceptions import LocalProtocolError
from .http import Http2Request, HttpRequest, TransportRequest

if False:
    from uuid import UUID

try:
    from urllib.parse import quote, urlencode, urlparse
except ImportError:
    from urllib import quote, urlencode  # type: ignore
    from urlparse import urlparse  # type: ignore


MATRIX_API_PATH = "/_matrix/client/r0"  # type: str
MATRIX_MEDIA_API_PATH = "/_matrix/media/r0"  # type: str


@unique
class MessageDirection(Enum):
    """Enum representing the direction messages should be fetched from."""

    back = 0
    front = 1


@unique
class ResizingMethod(Enum):
    """Enum representing the desired resizing method for a thumbnail.

    "scale" maintains the original aspect ratio of the image,
    "crop" provides an image in the aspect ratio of the requested size.
    """

    scale = "scale"
    crop = "crop"


@unique
class RoomVisibility(Enum):
    """Enum representing the desired visibility when creating a room.

    "public" means the room will be shown in the server's room directory.
    "private" will hide the room from the server's room directory.
    """

    private = "private"
    public = "public"


@unique
class RoomPreset(Enum):
    """Enum representing the available rule presets when creating a room.

    "private_chat" makes the room invite-only and allows guests.

    "trusted_private_chat" is the same as above, but also gives all invitees
    the same power level as the room's creator.

    "public_chat" makes the room joinable by anyone without invitations, and
    forbid guests.
    """

    private_chat = "private_chat"
    trusted_private_chat = "trusted_private_chat"
    public_chat = "public_chat"


class Api(object):
    """Matrix API class.

    Static methods reflecting the Matrix REST API.
    """

    @staticmethod
    def to_json(content_dict):
        # type: (Dict[Any, Any]) -> str
        """Turn a dictionary into a json string."""
        return json.dumps(content_dict, separators=(",", ":"))

    @staticmethod
    def to_canonical_json(content_dict):
        # type: (Dict[Any, Any]) -> str
        """Turn a dictionary into a canonical json string."""
        return json.dumps(
            content_dict,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def mimetype_to_msgtype(mimetype):
        # type: (str) -> str
        """Turn a mimetype into a matrix message type."""
        if mimetype.startswith("image"):
            return "m.image"
        elif mimetype.startswith("video"):
            return "m.video"
        elif mimetype.startswith("audio"):
            return "m.audio"

        return "m.file"

    @staticmethod
    def mxc_to_http(mxc, homeserver=None):
        # type: (str, Optional[str]) -> Optional[str]
        """Convert a matrix content URI to a HTTP URI."""
        url = urlparse(mxc)

        if url.scheme != "mxc":
            return None

        if not url.netloc or not url.path:
            return None

        parsed_homeserver = urlparse(homeserver) if homeserver else None

        http_url = (
            "{homeserver}/_matrix/media/r0/download/"
            "{server_name}{mediaId}"
        ).format(
            homeserver=(
                parsed_homeserver.geturl() if parsed_homeserver
                else "https://{}".format(url.netloc)
            ),
            server_name=url.hostname,
            mediaId=url.path
        )

        return http_url

    @staticmethod
    def encrypted_mxc_to_plumb(mxc, key, hash, iv, homeserver=None):
        # type: (str, str, str, str, Optional[str]) -> Optional[str]
        """Convert a matrix content URI to a encrypted mxc URI.

        The return value of this function will have a URI schema of emxc://.
        The path of the URI will be converted just like the mxc_to_http()
        function does, but it will also contain query parameters that are
        necessary to decrypt the payload the URI is pointing to.

        This function is useful to present a clickable URI that can be passed
        to a plumber program that will download and decrypt the content that
        the matrix content URI is pointing to.

        The returned URI should never be converted to http and opened directly,
        as that would expose the decryption parameters to any middleman or ISP.

        Args:
            mxc (str): The matrix content URI.
            key (str): The encryption key that can be used to decrypt the
                payload the URI is pointing to.
            hash (str): The hash of the payload.
            iv (str): The initial value needed to decrypt the payload.
        """
        url = urlparse(mxc)

        if url.scheme != "mxc":
            return None

        if not url.netloc or not url.path:
            return None

        parsed_homeserver = urlparse(homeserver) if homeserver else None

        host = (parsed_homeserver._replace(scheme="emxc").geturl()
                if parsed_homeserver else None)

        plumb_url = (
            "{homeserver}/_matrix/media/r0/download/"
            "{server_name}{mediaId}"
        ).format(
            homeserver=host if host else "emxc://{}".format(url.netloc),
            server_name=url.hostname,
            mediaId=url.path
        )

        query_parameters = {
            "key": key,
            "hash": hash,
            "iv": iv,
        }

        plumb_url += "?{}".format(urlencode(query_parameters))

        return plumb_url

    @staticmethod
    def _build_path(path, query_parameters=None, api_path=MATRIX_API_PATH):
        # type: (str, dict, str) -> str
        path = ("{api}/{path}").format(api=api_path, path=path)

        path = quote(path)

        if query_parameters:
            path += "?{}".format(urlencode(query_parameters))

        return path

    @staticmethod
    def login_info():
        # type: (...) -> Tuple[str, str]
        """Get the homeserver's supported login types

        Returns the HTTP method and HTTP path for the request.

        """
        path = Api._build_path("login")

        return "GET", path

    @staticmethod
    def login(
        user,            # type: str
        password=None,   # type: str
        device_name="",  # type: Optional[str]
        device_id="",    # type: Optional[str]
        token=None,      # type: str
    ):
        # type: (...) -> Tuple[str, str, str]
        """Authenticate the user.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            user (str): The fully qualified user ID or just local part of the
                user ID, to log in.
            password (str): The user's password.
            device_name (str): A display name to assign to a newly-created
                device. Ignored if device_id corresponds to a known device
            device_id (str): ID of the client device. If this does not
                correspond to a known client device, a new device will be
                created.
        """
        path = Api._build_path("login")

        if password is not None:
            content_dict = {
                "type": "m.login.password",
                "user": user,
                "password": password,
            }
        elif token is not None:
            content_dict = {
                "type": "m.login.token",
                "token": token,
            }
        else:
            raise ValueError("Neither a password nor a token was provided")

        if device_id:
            content_dict["device_id"] = device_id

        if device_name:
            content_dict["initial_device_display_name"] = device_name

        return "POST", path, Api.to_json(content_dict)

    @staticmethod
    def logout(
        access_token,     # type: str
        all_devices=False         # type: bool
    ):
        """Logout the session.

        Returns nothing.

        Args:
            access_token (str): the access token to be used with the request.
            all_devices (bool): Logout all sessions from all devices if set to True.
        """
        query_parameters = {"access_token": access_token}

        if all_devices:
            api_path = "logout/all"
        else:
            api_path = "logout"

        content_dict = {}  # type: Dict
        return (
            "POST",
            Api._build_path(api_path, query_parameters),
            Api.to_json(content_dict)
        )

    @staticmethod
    def sync(
        access_token,     # type: str
        since=None,       # type: Optional[str]
        timeout=None,     # type: Optional[int]
        filter=None,      # type: Optional[Dict[Any, Any]]
        full_state=None   # type: Optional[bool]
    ):
        # type: (...) -> Tuple[str, str]
        """Synchronise the client's state with the latest state on the server.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            since (str): The room id of the room where the event will be sent
                to.
            timeout(int): The maximum time to wait, in milliseconds, before
                returning this request.
            filter (Dict): A dictionary containing a filter configuration for
                the request.
        """
        query_parameters = {"access_token": access_token}

        if since:
            query_parameters["since"] = since

        if full_state is not None:
            query_parameters["full_state"] = str(full_state).lower()

        if timeout is not None:
            query_parameters["timeout"] = str(timeout)

        if filter is not None:
            filter_json = json.dumps(filter, separators=(",", ":"))
            query_parameters["filter"] = filter_json

        return "GET", Api._build_path("sync", query_parameters)

    @staticmethod
    def room_send(
        access_token,  # type: str
        room_id,       # type: str
        event_type,    # type: str
        body,          # type: Dict[Any, Any]
        tx_id          # type: Union[str, UUID]
    ):
        # type (...) -> Tuple[str, str, str]
        """Send a message event to a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room where the event will be sent
                to.
            event_type (str): The type of the message that will be sent.
            body(Dict): The body of the event. The fields in this
                object will vary depending on the type of event.
            tx_id (str): The transaction ID for this event.
        """
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/send/{msg_type}/{tx_id}".format(
            room=room_id, msg_type=event_type, tx_id=tx_id
        )

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_put_state(
        access_token, # type str
        room_id,      # type str
        event_type,   # type str
        body,         # type Dict[Any, Any]
        state_key=""  # type str
    ):
        # type (...) -> Tuple[str, str, str]
        """Send a state event.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room where the event will be sent
                to.
            event_type (str): The type of the event that will be sent.
            body(Dict): The body of the event. The fields in this
                object will vary depending on the type of event.
            state_key: The key of the state to look up. Defaults to an empty
                string.
        """
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/state/{event_type}/{state_key}".format(
            room=room_id, event_type=event_type, state_key=state_key
        )

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_get_state_event(access_token, room_id, event_type, state_key=""):
        # type (str, str, str) -> Tuple[str, str]
        """Fetch a state event.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room where the state is fetched
                from.
            event_type (str): The type of the event that will be fetched.
            state_key: The key of the state to look up. Defaults to an empty
                string.
        """
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/state/{event_type}/{state_key}".format(
            room=room_id, event_type=event_type, state_key=state_key
        )

        return (
            "GET",
            Api._build_path(path, query_parameters)
        )

    @staticmethod
    def room_get_state(access_token, room_id):
        # type (str, str) -> Tuple[str, str]
        """Fetch the current state for a room.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room where the state is fetched
                from.
        """
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/state".format(room=room_id)

        return (
            "GET",
            Api._build_path(path, query_parameters)
        )
    @staticmethod
    def room_redact(
        access_token,  # type: str
        room_id,       # type: str
        event_id,      # type: str
        tx_id,         # type: Union[str, UUID]
        reason=None    # type: Optional[str]
    ):
        # type (...) -> Tuple[str, str, str]
        """Strip information out of an event.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room that contains the event that
                will be redacted.
            event_id (str): The ID of the event that will be redacted.
            tx_id (str/UUID, optional): A transaction ID for this event.
            reason(str, optional): A description explaining why the
                event was redacted.
        """
        query_parameters = {"access_token": access_token}

        body = {}

        if reason:
            body["reason"] = reason

        path = "rooms/{room}/redact/{event_id}/{tx_id}".format(
            room=room_id, event_id=event_id, tx_id=tx_id
        )

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_kick(access_token, room_id, user_id, reason=None):
        # type (str, str, str, Optional[str]) -> Tuple[str, str, str]
        """Kick a user from a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room that the user will be
                kicked from.
            user_id (str): The user_id of the user that should be kicked.
        """
        query_parameters = {"access_token": access_token}

        body = {"user_id": user_id}

        if reason:
            body["reason"] = reason

        path = "rooms/{room}/kick".format(room=room_id)

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_invite(access_token, room_id, user_id):
        # type (str, str, str) -> Tuple[str, str, str]
        """Invite a user to a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room that the user will be
                invited to.
            user_id (str): The user id of the user that should be invited.
        """
        query_parameters = {"access_token": access_token}
        body = {"user_id": user_id}
        path = "rooms/{room}/invite".format(room=room_id)

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_create(
        access_token,                       # type: str
        visibility=RoomVisibility.private,  # type: RoomVisibility
        alias=None,                         # type: Optional[str]
        name=None,                          # type: Optional[str]
        topic=None,                         # type: Optional[str]
        room_version=None,                  # type: Optional[str]
        federate=True,                      # type: bool
        is_direct=False,                    # type: bool
        preset=None,                        # type: Optional[RoomPreset]
        invite=(),                          # type: Sequence[str]
        initial_state=(),                   # type: Sequence[Dict[str, Any]]
        power_level_override=None,          # type: Optional[Dict[str, Any]]
    ):
        # type (...) -> Tuple[str, str, str]
        """Create a new room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.

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
        path = "createRoom"
        query_parameters = {"access_token": access_token}

        body = {
            "visibility": visibility.value,
            "creation_content": {"m.federate": federate},
            "is_direct": is_direct,
        }

        if alias:
            body["room_alias_name"] = alias

        if name:
            body["name"] = name

        if topic:
            body["topic"] = topic

        if room_version:
            body["room_version"] = room_version

        if preset:
            body["preset"] = preset.value

        if invite:
            body["invite"] = list(invite)

        if initial_state:
            body["initial_state"] = list(initial_state)

        if power_level_override:
            body["power_level_content_override"] = power_level_override

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def join(access_token, room_id):
        # type (str, str) -> Tuple[str, str, str]
        """Join a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room identifier or alias to join.
        """
        query_parameters = {"access_token": access_token}
        body = {}
        path = "join/{room}".format(room=room_id)

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_leave(access_token, room_id):
        # type (str, str) -> Tuple[str, str, str]
        """Leave a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room that will be left.
        """
        query_parameters = {"access_token": access_token}
        body = {}
        path = "rooms/{room}/leave".format(room=room_id)

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_forget(access_token, room_id):
        # type (str, str) -> Tuple[str, str, str]
        """Forget a room.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room that will be forgotten.
        """
        query_parameters = {"access_token": access_token}
        body = {}
        path = "rooms/{room}/forget".format(room=room_id)

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def room_messages(
        access_token,                     # type: str
        room_id,                          # type: str
        start,                            # type: str
        end=None,                         # type: Optional[str]
        direction=MessageDirection.back,  # type: MessageDirection
        limit=10,                         # type: int
    ):
        # type (...) -> Tuple[str, str]
        """Get room messages.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): room id of the room for which to download the
                messages
            start (str): The token to start returning events from.
            end (str): The token to stop returning events at.
            direction (MessageDirection): The direction to return events from.
            limit (int): The maximum number of events to return.
        """
        query_parameters = {
            "access_token": access_token,
            "from": start,
            "limit": limit
        }

        if end:
            query_parameters["to"] = end

        if isinstance(direction, str):
            if direction in ("b", "back"):
                direction = MessageDirection.back
            elif direction in ("f", "fron"):
                direction = MessageDirection.front
            else:
                raise ValueError("Invalid direction")

        if direction is MessageDirection.front:
            query_parameters["dir"] = "f"
        else:
            query_parameters["dir"] = "b"

        path = "rooms/{room}/messages".format(room=room_id)

        return "GET", Api._build_path(path, query_parameters)

    @staticmethod
    def keys_upload(access_token, key_dict):
        # type: (str, Dict[str, Any]) -> Tuple[str, str, str]
        """Publish end-to-end encryption keys.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            key_dict (Dict): The dictionary containing device and one-time
                keys that will be published to the server.
        """
        query_parameters = {"access_token": access_token}
        body = key_dict
        path = "keys/upload"

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
        )

    @staticmethod
    def keys_query(access_token, user_set, token=None):
        # type: (str, Iterable[str], Optional[str]) -> Tuple[str, str, str]
        """Query the current devices and identity keys for the given users.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            user_set (Set[str]): The users for which the keys should be
                downloaded.
            token (Optional[str]): If the client is fetching keys as a result
                of a device update received in a sync request, this should be
                the 'since' token of that sync request, or any later sync
                token.
        """
        query_parameters = {"access_token": access_token}
        path = "keys/query"

        content = {
            "device_keys": {user: [] for user in user_set}
        }  # type: Dict[str, Dict[str, List]]

        if token:
            content["token"] = token  # type: ignore

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def keys_claim(access_token, user_set):
        # type: (str, Dict[str, Iterable[str]]) -> Tuple[str, str, str]
        """Claim one-time keys for use in Olm pre-key messages.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            user_set (Dict[str, List[str]]): The users and devices for which to
                claim one-time keys to be claimed. A map from user ID, to a
                list of device IDs.
        """
        query_parameters = {"access_token": access_token}
        path = "keys/claim"

        payload = defaultdict(dict)  # type: DefaultDict[str, Dict[str, str]]

        for user_id, device_list in user_set.items():
            for device_id in device_list:
                payload[user_id][device_id] = "signed_curve25519"

        content = {
            "one_time_keys": payload
        }

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def to_device(
        access_token,  # type: str
        event_type,    # type: str
        content,       # type: Dict[Any, Any]
        tx_id          # type: Union[str, UUID]
    ):
        # type: (...) -> Tuple[str, str, str]
        r"""Send to-device events to a set of client devices.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            event_type (str): The type of the event which will be sent.
            content (Dict): The messages to send. A map from user ID, to a map
                from device ID to message body. The device ID may also be \*,
                meaning all known devices for the user.
            tx_id (str): The transaction ID for this event.
        """
        query_parameters = {"access_token": access_token}
        path = "sendToDevice/{event_type}/{tx_id}".format(
            event_type=event_type,
            tx_id=tx_id
        )

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def devices(access_token):
        # type: (str) -> Tuple[str, str]
        """Get the list of devices for the current user.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
        """
        query_parameters = {"access_token": access_token}
        path = "devices"
        return "GET", Api._build_path(path, query_parameters)

    @staticmethod
    def update_device(access_token, device_id, content):
        # type: (str, Dict[str, str]) -> Tuple[str, str, str]
        """Update the metadata of the given device.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            device_id (str): The device for which the metadata will be updated.
            content (Dict): A dictionary of metadata values that will be
                updated for the device.
        """
        query_parameters = {"access_token": access_token}
        path = "devices/{}".format(device_id)

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def delete_devices(
        access_token,   # type: str
        devices,        # type: List[str]
        auth_dict=None  # type: Optional[Dict[str, str]]
    ):
        # type: (...) -> Tuple[str, str, str]
        """Delete a device.

        This API endpoint uses the User-Interactive Authentication API.

        This tells the server to delete the given devices and invalidate their
        associated access tokens.

        Should first be called with no additional authentication information.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            devices (List[str]): A list of devices which will be deleted.
            auth_dict (Dict): Additional authentication information for
                the user-interactive authentication API.
        """
        query_parameters = {"access_token": access_token}
        path = "delete_devices"

        content = {
            "devices": devices
        }  # type: Dict[str, Any]

        if auth_dict:
            content["auth"] = auth_dict

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def joined_members(access_token, room_id):
        # type: (str, str) -> Tuple[str, str]
        """Get the list of joined members for a room.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): Room id of the room where the user is typing.
        """
        query_parameters = {"access_token": access_token}
        path = "rooms/{}/joined_members".format(room_id)

        return "GET", Api._build_path(path, query_parameters)

    @staticmethod
    def joined_rooms(access_token):
        # type: (str) -> Tuple[str, str]
        """Get the list of joined rooms for the logged in account.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
        """
        query_parameters = {"access_token": access_token}
        path = "joined_rooms"

        return "GET", Api._build_path(path, query_parameters)

    @staticmethod
    def room_resolve_alias(room_alias):
        # type: (str) -> Tuple[str, str]
        """Resolve a room alias to a room ID.

        Returns the HTTP method and HTTP path for the request.

        Args:
            room_alias (str): The alias to resolve
        """
        path = "directory/room/{}".format(room_alias)

        return "GET", Api._build_path(path)

    @staticmethod
    def room_typing(
        access_token,       # type: str
        room_id,            # type: str
        user_id,            # type: str
        typing_state=True,  # type: bool
        timeout=30000       # type: int
    ):
        # type: (...) -> Tuple[str, str, str]
        """Send a typing notice to the server.

        This tells the server that the user is typing for the next N
        milliseconds or that the user has stopped typing.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): Room id of the room where the user is typing.
            user_id (str): The user who has started to type.
            typing_state (bool): A flag representing whether the user started
                or stopped typing
            timeout (int): For how long should the new typing notice be
                valid for in milliseconds.
        """
        query_parameters = {"access_token": access_token}
        path = "rooms/{}/typing/{}".format(room_id, user_id)

        content = {
            "typing": typing_state
        }

        if typing_state:
            content["timeout"] = timeout  # type: ignore

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def room_read_markers(
        access_token,       # type: str
        room_id,            # type: str
        fully_read_event,   # type: str
        read_event=None,    # type: Optional[str]
    ):
        # type: (...) -> Tuple[str, str, str]
        """Update read markers for a room.

        This sets the position of the read marker for a given room,
        and optionally the read receipt's location.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): Room id of the room of the room where the read
                markers should be updated
            fully_read_event (str): The event ID the read marker should be
                located at.
            read_event (Optional[str]): The event ID to set the read receipt
                location at.
        """
        query_parameters = {"access_token": access_token}
        path = "rooms/{}/read_markers".format(room_id)

        content = {
            "m.fully_read": fully_read_event
        }

        if read_event:
            content["m.read"] = read_event

        return (
            "POST",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def upload(
        access_token,       # type: str
        filename=None,      # type: Optional[str]
    ):
        # type: (...) -> Tuple[str, str, str]
        """Upload a file's content to the content repository.

        Returns the HTTP method, HTTP path and empty data for the request.
        The real data should be read from the file that should be uploaded.

        Note: This requests also requires the Content-Type http header to be
        set.

        Args:
            access_token (str): The access token to be used with the request.
            filename (str): The name of the file being uploaded
        """
        query_parameters = {"access_token": access_token}
        path = "upload"

        if filename:
            query_parameters["filename"] = filename

        return (
            "POST",
            Api._build_path(path, query_parameters, MATRIX_MEDIA_API_PATH),
            ""
        )

    @staticmethod
    def download(
        server_name,        # type: str
        media_id,           # type: str
        filename=None,      # type: Optional[str]
        allow_remote=True,  # type: bool
    ):
        # type: (...) -> Tuple[str, str]
        """Get the content of a file from the content repository.

        Returns the HTTP method and HTTP path for the request.

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
        query_parameters = {
            "allow_remote": "true" if allow_remote else "false",
        }
        end = "/{}".format(filename) if filename else ""
        path = "download/{}/{}{}".format(server_name, media_id, end)

        return (
            "GET",
            Api._build_path(path, query_parameters, MATRIX_MEDIA_API_PATH)
        )

    @staticmethod
    def thumbnail(
        server_name,                  # type: str
        media_id,                     # type: str
        width,                        # type: int
        height,                       # type: int
        method=ResizingMethod.scale,  # ŧype: ResizingMethod
        allow_remote=True,            # type: bool
    ):
        # type: (...) -> Tuple[str, str]
        """Get the thumbnail of a file from the content repository.

        Returns the HTTP method and HTTP path for the request.

        Note: The actual thumbnail may be larger than the size specified.

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
        query_parameters = {
            "width": width,
            "height": height,
            "method": method.value,
            "allow_remote": "true" if allow_remote else "false",
        }
        path = "thumbnail/{}/{}".format(server_name, media_id)

        return (
            "GET",
            Api._build_path(path, query_parameters, MATRIX_MEDIA_API_PATH)
        )

    @staticmethod
    def profile_get(user_id):
        # type (str, str) -> Tuple[str, str]
        """Get the combined profile information for a user.

        Returns the HTTP method and HTTP path for the request.

        Args:
            user_id (str): User id to get the profile for.
        """
        path = "profile/{user}".format(user=user_id)

        return "GET", Api._build_path(path)

    @staticmethod
    def profile_get_displayname(user_id):
        # type (str, str) -> Tuple[str, str]
        """Get display name.

        Returns the HTTP method and HTTP path for the request.

        Args:
            user_id (str): User id to get display name for.
        """
        path = "profile/{user}/displayname".format(user=user_id)

        return "GET", Api._build_path(path)

    @staticmethod
    def profile_set_displayname(access_token, user_id, display_name):
        # type (str, str, str) -> Tuple[str, str, str]
        """Set display name.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            user_id (str): User id to set display name for.
            display_name (str): Display name for user to set.
        """
        query_parameters = {"access_token": access_token}
        content = {"displayname": display_name}
        path = "profile/{user}/displayname".format(user=user_id)

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def profile_get_avatar(user_id):
        # type (str, str) -> Tuple[str, str]
        """Get avatar URL.

        Returns the HTTP method and HTTP path for the request.

        Args:
            user_id (str): User id to get avatar for.
        """
        path = "profile/{user}/avatar_url".format(user=user_id)

        return "GET", Api._build_path(path)

    @staticmethod
    def profile_set_avatar(access_token, user_id, avatar_url):
        # type (str, str, str) -> Tuple[str, str, str]
        """Set avatar url.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            user_id (str): User id to set display name for.
            avatar_url (str): matrix content URI of the avatar to set.
        """
        query_parameters = {"access_token": access_token}
        content = {"avatar_url": avatar_url}
        path = "profile/{user}/avatar_url".format(user=user_id)

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(content)
        )

    @staticmethod
    def whoami(access_token):
        # type (str) -> Tuple[str, str]
        """Get information about the owner of a given access token.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
        """
        query_parameters = {"access_token": access_token}
        path = "account/whoami"

        return "GET", Api._build_path(path, query_parameters)

    @staticmethod
    def room_context(access_token, room_id, event_id, limit=None):
        # type (str) -> Tuple[str, str]
        """Fetch a number of events that happened before and after an event.
        This allows clients to get the context surrounding an event.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room_id of the room that contains the event and
                its context.
            event_id (str): The event_id of the event that we wish to get the
                context for.
            limit(int, optional): The maximum number of events to request.
        """
        query_parameters = {"access_token": access_token}

        if limit:
            query_parameters["limit"] = limit

        path = "rooms/{room}/context/{event_id}".format(
            room=room_id, event_id=event_id
        )

        return "GET", Api._build_path(path, query_parameters)
