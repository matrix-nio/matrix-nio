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

"""nio api module.

This module contains primitives to build Matrix API http requests.
"""


from __future__ import unicode_literals

import json
from collections import defaultdict
from enum import Enum, unique
from typing import (Any, DefaultDict, Dict, Iterable, List, Optional, Set,
                    Tuple, Union)

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
    def mxc_to_http(mxc):
        # type: (str) -> Optional[str]
        """Convert a matrix content URI to a HTTP URI."""
        url = urlparse(mxc)

        if url.scheme != "mxc":
            return None

        if not url.netloc or not url.path:
            return None

        http_url = (
            "https://{host}/_matrix/media/r0/download/"
            "{server_name}{mediaId}"
        ).format(host=url.netloc, server_name=url.netloc, mediaId=url.path)

        return http_url

    @staticmethod
    def encrypted_mxc_to_plumb(mxc, key, hash, iv):
        # type: (str, str, str, str) -> Optional[str]
        """Convert a matrix content URI to a encrypted mxc URI.

        The return value of this function will have a URI schema of emxc://.
        The path of the URI will be converted just like the mxc_to_http()
        function does, but it will also contain query parameters that are
        necessary to decrypt the payload the URI is pointing to.

        This function is useful to present a clickable URI that can be passed
        to a plumber program that will download and decrypt the content that
        the matrix content URI is pointing to.

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

        plumb_url = (
            "emxc://{host}/_matrix/media/r0/download/"
            "{server_name}{mediaId}"
        ).format(host=url.netloc, server_name=url.netloc, mediaId=url.path)

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

        if query_parameters:
            path += "?{}".format(urlencode(query_parameters))

        return path

    @staticmethod
    def login(
        user,            # type: str
        password,        # type: str
        device_name="",  # type: Optional[str]
        device_id=""     # type: Optional[str]
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

        content_dict = {
            "type": "m.login.password",
            "user": user,
            "password": password,
        }

        if device_id:
            content_dict["device_id"] = device_id

        if device_name:
            content_dict["initial_device_display_name"] = device_name

        return "POST", path, Api.to_json(content_dict)

    @staticmethod
    def sync(
        access_token,     # type: str
        since=None,       # type: Optional[str]
        timeout=None,     # type: Optional[int]
        filter=None,      # type: Optional[Dict[Any, Any]]
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
    def room_put_state(access_token, room_id, event_type, body):
        # type (str, str, str, Dict[Any, Any]) -> Tuple[str, str, str]
        """Send a state event.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): The room id of the room where the event will be sent
                to.
            event_type (str): The type of the event that will be sent.
            body(Dict): The body of the event. The fields in this
                object will vary depending on the type of event.
        """
        query_parameters = {"access_token": access_token}

        path = "rooms/{room}/state/{event_type}".format(
            room=room_id, event_type=event_type
        )

        return (
            "PUT",
            Api._build_path(path, query_parameters),
            Api.to_json(body)
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
            tx_id (str): The transaction ID for this event.
            reason(str): A description explaining why the event was redacted.
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
            user_id (str): The user_id of the user that should be invited.
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

        This tells the server that the user is typing for the next N
        milliseconds or that the user has stopped typing.

        Returns the HTTP method and HTTP path for the request.

        Args:
            access_token (str): The access token to be used with the request.
            room_id (str): Room id of the room where the user is typing.
        """
        query_parameters = {"access_token": access_token}
        path = "rooms/{}/joined_members".format(room_id)

        return "GET", Api._build_path(path, query_parameters)

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
            typign_state (bool): A flag representing whether the user started
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
        filename=None,      # type: str
    ):
        # type: (...) -> Tuple[str, str, str]
        """Upload some content to the content repository.

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
    def profile_get_displayname(access_token, user_id):
        # type (str, str) -> Tuple[str, str, str]
        """Get display name.

        Returns the HTTP method, HTTP path and data for the request.

        Args:
            access_token (str): The access token to be used with the request.
            user_id (str): User id to get display name for.
        """
        query_parameters = {"access_token": access_token}
        path = "profile/{user}/displayname".format(user=user_id)

        return (
            "GET",
            Api._build_path(path, query_parameters),
            ""
        )

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
