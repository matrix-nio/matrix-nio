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

from builtins import str
from datetime import datetime
from functools import wraps
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import attr
from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .events import (AccountDataEvent, BadEventType, Event, InviteEvent,
                     ToDeviceEvent, UnknownBadEvent)
from .log import logger_group
from .schemas import Schemas, validate_json

logger = Logger("nio.responses")
logger_group.add_logger(logger)


__all__ = [
    "DeleteDevicesAuthResponse",
    "DeleteDevicesResponse",
    "DeleteDevicesError",
    "Device",
    "DeviceList",
    "DevicesResponse",
    "DevicesError",
    "DeviceOneTimeKeyCount",
    "ErrorResponse",
    "InviteInfo",
    "JoinResponse",
    "JoinError",
    "JoinedMembersResponse",
    "JoinedMembersError",
    "KeysClaimResponse",
    "KeysClaimError",
    "KeysQueryResponse",
    "KeysQueryError",
    "KeysUploadResponse",
    "KeysUploadError",
    "LoginResponse",
    "LoginError",
    "Response",
    "RoomInfo",
    "RoomInviteResponse",
    "RoomInviteError",
    "RoomKickResponse",
    "RoomKickResponse",
    "RoomLeaveResponse",
    "RoomLeaveError",
    "RoomForgetResponse",
    "RoomForgetError",
    "RoomMember",
    "RoomMessagesResponse",
    "RoomMessagesError",
    "RoomPutStateResponse",
    "RoomPutStateError",
    "RoomRedactResponse",
    "RoomRedactError",
    "RoomSendResponse",
    "RoomSendError",
    "RoomSummary",
    "Rooms",
    "ShareGroupSessionResponse",
    "ShareGroupSessionError",
    "SyncResponse",
    "PartialSyncResponse",
    "SyncError",
    "Timeline",
    "TypingNoticeEvent",
    "UpdateDeviceResponse",
    "UpdateDeviceError",
    "RoomTypingResponse",
    "RoomTypingError",
    "RoomReadMarkersResponse",
    "RoomReadMarkersError",
    "UploadResponse",
    "UploadError",
    "ProfileGetDisplayNameResponse",
    "ProfileGetDisplayNameError",
    "ProfileSetDisplayNameResponse",
    "ProfileSetDisplayNameError",
    "RoomKeyRequestResponse",
    "RoomKeyRequestError",
    "ToDeviceResponse",
    "ToDeviceError",
]


def verify(schema, error_class, pass_arguments=True):
    def decorator(f):
        @wraps(f)
        def wrapper(cls, parsed_dict, *args, **kwargs):
            try:
                logger.info("Validating response schema")
                validate_json(parsed_dict, schema)
            except (SchemaError, ValidationError) as e:
                logger.error("Error validating response: " + str(e.message))

                if pass_arguments:
                    return error_class.from_dict(parsed_dict, *args, **kwargs)
                else:
                    return error_class.from_dict(parsed_dict)

            return f(cls, parsed_dict, *args, **kwargs)
        return wrapper
    return decorator


@attr.s
class Rooms(object):
    invite = attr.ib(type=Dict)
    join = attr.ib(type=Dict)
    leave = attr.ib(type=Dict)


@attr.s
class DeviceOneTimeKeyCount(object):
    curve25519 = attr.ib(type=int)
    signed_curve25519 = attr.ib(type=int)


@attr.s
class DeviceList(object):
    changed = attr.ib(type=List[str])
    left = attr.ib(type=List[str])


@attr.s
class Timeline(object):
    events = attr.ib(type=List)
    limited = attr.ib(type=bool)
    prev_batch = attr.ib(type=str)


@attr.s
class InviteInfo(object):
    invite_state = attr.ib(type=List)


@attr.s
class TypingNoticeEvent(object):
    users = attr.ib(type=List)


@attr.s
class RoomSummary(object):
    invited_member_count = attr.ib(default=None, type=Optional[int])
    joined_member_count = attr.ib(default=None, type=Optional[int])
    heroes = attr.ib(default=[], type=List[str])


@attr.s
class RoomInfo(object):
    timeline = attr.ib(type=Timeline)
    state = attr.ib(type=List)
    ephemeral = attr.ib(type=List)
    account_data = attr.ib(type=List)
    summary = attr.ib(default=None, type=Optional[RoomSummary])

    @staticmethod
    def parse_account_data(event_dict):
        """Parse the account data dictionary and produce a list of events."""
        events = []

        for event in event_dict:
            events.append(AccountDataEvent.parse_event(event))

        return events


@attr.s
class RoomMember(object):
    user_id = attr.ib(type=str)
    display_name = attr.ib(type=str)
    avatar_url = attr.ib(type=str)


@attr.s
class Device(object):
    id = attr.ib(type=str)
    display_name = attr.ib(type=str)
    last_seen_ip = attr.ib(type=str)
    last_seen_date = attr.ib(type=datetime)

    @classmethod
    def from_dict(cls, parsed_dict):
        date = None

        if parsed_dict["last_seen_ts"] is not None:
            date = datetime.fromtimestamp(parsed_dict["last_seen_ts"] / 1000)

        return cls(
            parsed_dict["device_id"],
            parsed_dict["display_name"],
            parsed_dict["last_seen_ip"],
            date
        )


@attr.s
class Response(object):
    uuid = ""          # type : str
    start_time = None  # type : Optional[float]
    end_time = None    # type : Optional[float]
    timeout = 0        # type : int
    transport_response = attr.ib(init=False, default=None)

    @property
    def elapsed(self):
        if not self.start_time or not self.end_time:
            return 0
        elapsed = self.end_time - self.start_time
        return max(0, elapsed - (self.timeout / 1000))


@attr.s
class ErrorResponse(Response):
    message = attr.ib(type=str)
    status_code = attr.ib(default=None, type=Optional[int])

    def __str__(self):
        # type: () -> str
        if self.status_code and self.message:
            e = "{} {}".format(self.status_code, self.message)
        elif self.message:
            e = self.message
        elif self.status_code:
            e = "{} unknown error".format(self.status_code)
        else:
            e = "unknown error"

        return "{}: {}".format(self.__class__.__name__, e)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> ErrorResponse
        try:
            validate_json(parsed_dict, Schemas.error)
        except (SchemaError, ValidationError):
            return cls("unknown error")

        return cls(parsed_dict["error"], parsed_dict["errcode"])


@attr.s
class _ErrorWithRoomId(ErrorResponse):
    room_id = attr.ib(default="", type=str)

    @classmethod
    def from_dict(cls, parsed_dict, room_id):
        try:
            validate_json(parsed_dict, Schemas.error)
        except (SchemaError, ValidationError):
            return cls("unknown error")

        return cls(parsed_dict["error"], parsed_dict["errcode"], room_id)


class LoginError(ErrorResponse):
    pass


class SyncError(ErrorResponse):
    pass


class RoomSendError(_ErrorWithRoomId):
    pass


class RoomPutStateError(_ErrorWithRoomId):
    pass


class RoomRedactError(_ErrorWithRoomId):
    pass


class RoomTypingError(_ErrorWithRoomId):
    """A response representing a unsuccessful room typing request."""

    pass


class RoomReadMarkersError(_ErrorWithRoomId):
    """A response representing a unsuccessful room read markers request."""

    pass


class RoomKickError(ErrorResponse):
    pass


class RoomInviteError(ErrorResponse):
    pass


class JoinError(ErrorResponse):
    pass


class RoomLeaveError(ErrorResponse):
    pass


class RoomForgetError(_ErrorWithRoomId):
    pass


class RoomMessagesError(ErrorResponse):
    pass


class KeysUploadError(ErrorResponse):
    pass


class KeysQueryError(ErrorResponse):
    pass


class KeysClaimError(_ErrorWithRoomId):
    pass


class UploadError(ErrorResponse):
    """A response representing a unsuccessful upload request."""

    pass


@attr.s
class ShareGroupSessionError(_ErrorWithRoomId):
    """Response representing unsuccessful group sessions sharing request."""

    users_shared_with = attr.ib(type=set, default=None)

    @classmethod
    def from_dict(cls, parsed_dict, room_id, users_shared_with):
        try:
            validate_json(parsed_dict, Schemas.error)
        except (SchemaError, ValidationError):
            return cls("unknown error")

        return cls(parsed_dict["error"], parsed_dict["errcode"], room_id,
                   users_shared_with)


class DevicesError(ErrorResponse):
    pass


class DeleteDevicesError(ErrorResponse):
    pass


class UpdateDeviceError(ErrorResponse):
    pass


class JoinedMembersError(_ErrorWithRoomId):
    pass


class ProfileGetDisplayNameError(ErrorResponse):
    pass


class ProfileSetDisplayNameError(ErrorResponse):
    pass


@attr.s
class LoginResponse(Response):
    user_id = attr.ib(type=str)
    device_id = attr.ib(type=str)
    access_token = attr.ib(type=str)

    def __str__(self):
        # type: () -> str
        return "Logged in as {}, device id: {}.".format(
            self.user_id, self.device_id
        )

    @classmethod
    @verify(Schemas.login, LoginError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[LoginResponse, ErrorResponse]
        return cls(
            parsed_dict["user_id"],
            parsed_dict["device_id"],
            parsed_dict["access_token"],
        )


@attr.s
class JoinedMembersResponse(Response):
    members = attr.ib(type=List[RoomMember])
    room_id = attr.ib(type=str)

    @classmethod
    @verify(Schemas.joined_members, JoinedMembersError)
    def from_dict(
        cls,
        parsed_dict,  # type: Dict[Any, Any]
        room_id       # type: str
    ):
        # type: (...) -> Union[JoinedMembersResponse, ErrorResponse]
        members = []

        for user_id, user_info in parsed_dict["joined"].items():
            user = RoomMember(
                user_id,
                user_info.get("display_name", None),
                user_info.get("avatar_url", None)
            )
            members.append(user)

        return cls(members, room_id)


@attr.s
class UploadResponse(Response):
    """A response representing a successful upload request."""

    content_uri = attr.ib(type=str)

    @classmethod
    @verify(Schemas.upload, UploadError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[UploadResponse, ErrorResponse]
        return cls(
            parsed_dict["content_uri"],
        )


@attr.s
class RoomEventIdResponse(Response):
    event_id = attr.ib(type=str)
    room_id = attr.ib(type=str)

    @staticmethod
    def create_error(parsed_dict, _room_id):
        return ErrorResponse.from_dict(parsed_dict)

    @classmethod
    def from_dict(
        cls,
        parsed_dict,  # type: Dict[Any, Any]
        room_id       # type: str
    ):
        # type: (...) -> Union[RoomEventIdResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.room_event_id)
        except (SchemaError, ValidationError):
            return cls.create_error(parsed_dict, room_id)

        return cls(parsed_dict["event_id"], room_id)


class RoomSendResponse(RoomEventIdResponse):
    @staticmethod
    def create_error(parsed_dict, room_id):
        return RoomSendError.from_dict(parsed_dict, room_id)


class RoomPutStateResponse(RoomEventIdResponse):
    @staticmethod
    def create_error(parsed_dict, room_id):
        return RoomPutStateError.from_dict(parsed_dict, room_id)


class RoomRedactResponse(RoomEventIdResponse):
    @staticmethod
    def create_error(parsed_dict, room_id):
        return RoomRedactError.from_dict(parsed_dict, room_id)


class EmptyResponse(Response):
    @staticmethod
    def create_error(parsed_dict):
        return ErrorResponse.from_dict(parsed_dict)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[Any, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.empty)
        except (SchemaError, ValidationError):
            return cls.create_error(parsed_dict)

        return cls()


@attr.s
class _EmptyResponseWithRoomId(Response):
    room_id = attr.ib(type=str)

    @staticmethod
    def create_error(parsed_dict, room_id):
        return _ErrorWithRoomId.from_dict(parsed_dict, room_id)

    @classmethod
    def from_dict(cls, parsed_dict, room_id):
        # type: (Dict[Any, Any], str) -> Union[Any, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.empty)
        except (SchemaError, ValidationError):
            return cls.create_error(parsed_dict, room_id)

        return cls(room_id)


class RoomKickResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return RoomKickError.from_dict(parsed_dict)


class RoomInviteResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return RoomInviteError.from_dict(parsed_dict)


@attr.s
class ShareGroupSessionResponse(Response):
    """Response representing a successful group sessions sharing request.

    Attributes:
        room_id (str): The room id of the group session.
        users_shared_with: (Set[Tuple[str, str]]): A set containing a tuple of
            user id device id pairs with whom we shared the group session in
            this request.

    """

    room_id = attr.ib(type=str)
    users_shared_with = attr.ib(type=set)

    @classmethod
    @verify(Schemas.empty, ShareGroupSessionError)
    def from_dict(
        cls,
        _,                 # type: Dict[Any, Any]
        room_id,           # type: str
        users_shared_with  # type: Set[Tuple[str, str]]
    ):
        # type: (...) -> Union[ShareGroupSessionResponse, ErrorResponse]
        """Create a response from the json dict the server returns.

        Args:
           parsed_dict (Dict): The dict containing the raw json response.
           room_id (str): The room id of the room to which the group session
               belongs to.
           users_shared_with: (Set[Tuple[str, str]]): A set containing a tuple
               of user id device id pairs with whom we shared the group
               session in this request.
        """
        return cls(room_id, users_shared_with)


class RoomTypingResponse(_EmptyResponseWithRoomId):
    """A response representing a successful room typing request."""

    @staticmethod
    def create_error(parsed_dict, room_id):
        return RoomTypingError.from_dict(parsed_dict, room_id)


class RoomReadMarkersResponse(_EmptyResponseWithRoomId):
    """A response representing a successful room read markers request."""

    @staticmethod
    def create_error(parsed_dict, room_id):
        return RoomTypingError.from_dict(parsed_dict, room_id)


@attr.s
class DeleteDevicesAuthResponse(Response):
    session = attr.ib(type=str)
    flows = attr.ib(type=Dict)
    params = attr.ib(type=Dict)

    @classmethod
    @verify(Schemas.delete_devices, DeleteDevicesError)
    def from_dict(
        cls,
        parsed_dict  # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[DeleteDevicesAuthResponse, ErrorResponse]
        return cls(
            parsed_dict["session"],
            parsed_dict["flows"],
            parsed_dict["params"]
        )


class DeleteDevicesResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return DeleteDevicesError.from_dict(parsed_dict)


@attr.s
class RoomMessagesResponse(Response):
    chunk = attr.ib(type=List[Union[Event, BadEventType]])
    start = attr.ib(type=str)
    end = attr.ib(type=str)

    @classmethod
    @verify(Schemas.room_messages, RoomMessagesError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMessagesResponse, ErrorResponse]
        chunk = []  # type: List[Union[Event, BadEventType]]
        _, chunk = SyncResponse._get_room_events(parsed_dict["chunk"])
        return cls(chunk, parsed_dict["start"], parsed_dict["end"])


@attr.s
class RoomIdResponse(Response):
    room_id = attr.ib(type=str)

    @staticmethod
    def create_error(parsed_dict):
        return ErrorResponse.from_dict(parsed_dict)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomIdResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.room_id)
        except (SchemaError, ValidationError):
            return cls.create_error(parsed_dict)

        return cls(parsed_dict["room_id"])


class JoinResponse(RoomIdResponse):
    @staticmethod
    def create_error(parsed_dict):
        return JoinError.from_dict(parsed_dict)


class RoomLeaveResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return RoomLeaveError.from_dict(parsed_dict)


class RoomForgetResponse(_EmptyResponseWithRoomId):
    """Response representing a successful forget room request."""
    @staticmethod
    def create_error(parsed_dict):
        return RoomForgetError.from_dict(parsed_dict)


@attr.s
class KeysUploadResponse(Response):
    curve25519_count = attr.ib(type=int)
    signed_curve25519_count = attr.ib(type=int)

    @classmethod
    @verify(Schemas.keys_upload, KeysUploadError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[KeysUploadResponse, ErrorResponse]
        counts = parsed_dict["one_time_key_counts"]
        return cls(counts["curve25519"], counts["signed_curve25519"])


@attr.s
class KeysQueryResponse(Response):
    device_keys = attr.ib(type=Dict)
    failures = attr.ib(type=Dict)
    changed = attr.ib(
        type=Dict[str, Dict[str, Any]],
        init=False,
        factory=dict
    )

    @classmethod
    @verify(Schemas.keys_query, KeysQueryError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[KeysQueryResponse, ErrorResponse]
        device_keys = parsed_dict["device_keys"]
        failures = parsed_dict["failures"]

        return cls(device_keys, failures)


@attr.s
class KeysClaimResponse(Response):
    one_time_keys = attr.ib(type=Dict[Any, Any])
    failures = attr.ib(type=Dict[Any, Any])
    room_id = attr.ib(type=str, default="")

    @classmethod
    @verify(Schemas.keys_claim, KeysClaimError)
    def from_dict(
        cls,
        parsed_dict,  # type: Dict[Any, Any]
        room_id=""    # type: str
    ):
        # type: (...) -> Union[KeysClaimResponse, ErrorResponse]
        one_time_keys = parsed_dict["one_time_keys"]
        failures = parsed_dict["failures"]

        return cls(one_time_keys, failures, room_id)


@attr.s
class DevicesResponse(Response):
    devices = attr.ib(type=List[Device])

    @classmethod
    @verify(Schemas.devices, DevicesError)
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[DevicesResponse, ErrorResponse]
        devices = []
        for device_dict in parsed_dict["devices"]:
            try:
                device = Device.from_dict(device_dict)
            except ValueError:
                continue
            devices.append(device)

        return cls(devices)


@attr.s
class RoomKeyRequestError(ErrorResponse):
    """Response representing a failed room key request."""

    pass


@attr.s
class RoomKeyRequestResponse(Response):
    """Response representing a successful room key request.

    Attributes:
        request_id (str): The id of the that uniquely identifies this key
            request that was requested, if we receive a to_device event it will
            contain the same request id.
        session_id (str): The id of the session that we requested.
        room_id (str): The id of the room that the session belongs to.
        algorithm (str): The encryption algorithm of the session.

    """

    request_id = attr.ib(type=str)
    session_id = attr.ib(type=str)
    room_id = attr.ib(type=str)
    algorithm = attr.ib(type=str)

    @classmethod
    @verify(Schemas.empty, RoomKeyRequestError, False)
    def from_dict(cls, _, request_id, session_id, room_id, algorithm):
        """Create a RoomKeyRequestResponse from a json response.

        Args:
            parsed_dict (Dict): The dictionary containing the json response.
            request_id (str): The id of that uniquely identifies this key
                request that was requested, if we receive a to_device event
                it will contain the same request id.
            session_id (str): The id of the session that we requested.
            room_id (str): The id of the room that the session belongs to.
            algorithm (str): The encryption algorithm of the session.
        """
        return cls(request_id, session_id, room_id, algorithm)


class UpdateDeviceResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return UpdateDeviceError.from_dict(parsed_dict)


@attr.s
class ProfileGetDisplayNameResponse(Response):
    """Response representing a successful get display name request.

    Attributes:
        displayname (str, optional): The display name of the user.
            None if the user doesn't have a display name.
    """

    displayname = attr.ib(type=Optional[str], default=None)

    def __str__(self):
        # type: () -> str
        return "Display name: {}".format(self.displayname)

    @classmethod
    @verify(Schemas.get_displayname, ProfileGetDisplayNameError)
    def from_dict(
        cls,
        parsed_dict  # type: (Dict[Any, Any])
    ):
        # type: (...) -> Union[ProfileGetDisplayNameResponse, ErrorResponse]
        return cls(parsed_dict.get("displayname"))


class ProfileSetDisplayNameResponse(EmptyResponse):
    @staticmethod
    def create_error(parsed_dict):
        return ProfileSetDisplayNameError.from_dict(parsed_dict)


@attr.s
class ToDeviceError(ErrorResponse):
    """Response representing a unsuccessful room key request."""

    to_device_message = attr.ib(default=None)

    @classmethod
    def from_dict(cls, parsed_dict, message):
        try:
            validate_json(parsed_dict, Schemas.error)
        except (SchemaError, ValidationError):
            return cls("unknown error", None, message)

        return cls(parsed_dict["error"], parsed_dict["errcode"], message)


@attr.s
class ToDeviceResponse(Response):
    """Response representing a successful room key request."""

    to_device_message = attr.ib()

    @classmethod
    @verify(Schemas.empty, ToDeviceError)
    def from_dict(cls, parsed_dict, message):
        """Create a ToDeviceResponse from a json response."""
        return cls(message)


@attr.s
class _SyncResponse(Response):
    next_batch = attr.ib(type=str)
    rooms = attr.ib(type=Rooms)
    device_key_count = attr.ib(type=DeviceOneTimeKeyCount)
    device_list = attr.ib(type=DeviceList)
    to_device_events = attr.ib(type=List[ToDeviceEvent])

    def __str__(self):
        # type: () -> str
        room_messages = []
        for room_id, room_info in self.rooms.join.items():
            room_header = "  Messages for room {}:\n    ".format(room_id)
            messages = []
            for event in room_info.timeline.events:
                messages.append(str(event))

            room_message = room_header + "\n    ".join(messages)
            room_messages.append(room_message)

        body = "\n".join(room_messages)
        string = ("Sync response until batch: {}:\n{}").format(
            self.next_batch, body
        )
        return string

    @staticmethod
    def _get_room_events(
            parsed_dict,  # type: List[Dict[Any, Any]]
            max_events=0  # type: int
    ):
        # type: (...) -> Tuple[int, List[Union[Event, BadEventType]]]
        events = []  # type: List[Union[Event, BadEventType]]
        counter = 0

        for counter, event_dict in enumerate(parsed_dict, 1):
            try:
                validate_json(event_dict, Schemas.room_event)
            except (SchemaError, ValidationError) as e:
                logger.error("Error validating event: {}".format(str(e)))
                events.append(UnknownBadEvent(event_dict))
                continue

            event = Event.parse_event(event_dict)

            if event:
                events.append(event)

            if max_events > 0 and counter >= max_events:
                break

        return counter, events

    @staticmethod
    def _get_to_device(parsed_dict):
        # type: (Dict[Any, Any]) -> List[ToDeviceEvent]
        events = []  # type: List[ToDeviceEvent]
        for event_dict in parsed_dict["events"]:
            event = ToDeviceEvent.parse_event(event_dict)

            if event:
                events.append(event)

        return events

    @staticmethod
    def _get_timeline(parsed_dict, max_events=0):
        # type: (Dict[Any, Any], int) -> Tuple[int, Timeline]
        validate_json(parsed_dict, Schemas.room_timeline)

        counter, events = _SyncResponse._get_room_events(
            parsed_dict["events"],
            max_events
        )

        return counter, Timeline(
            events, parsed_dict["limited"], parsed_dict["prev_batch"]
        )

    @staticmethod
    def _get_state(parsed_dict, max_events=0):
        validate_json(parsed_dict, Schemas.room_state)
        counter, events = _SyncResponse._get_room_events(
            parsed_dict["events"],
            max_events
        )

        return counter, events

    @staticmethod
    def _get_invite_state(parsed_dict):
        validate_json(parsed_dict, Schemas.room_state)
        events = []

        for event_dict in parsed_dict["events"]:
            event = InviteEvent.parse_event(event_dict)

            if event:
                events.append(event)

        return events

    @staticmethod
    def _get_ephemeral_events(parsed_dict):
        events = []
        for event in parsed_dict:
            try:
                validate_json(event, Schemas.ephemeral_event)
            except (SchemaError, ValidationError):
                continue

            if event["type"] == "m.typing":
                try:
                    validate_json(event, Schemas.m_typing)
                except (SchemaError, ValidationError) as e:
                    logger.error(
                        "Error validating typing notice event: "
                        + str(e.message)
                    )
                    continue
                events.append(TypingNoticeEvent(event["content"]["user_ids"]))
        return events

    @staticmethod
    def _get_join_info(
        state_events,         # type: List[Any]
        timeline_events,      # type: List[Any]
        prev_batch,           # type: str
        limited,              # type: bool
        ephemeral_events,     # type: List[Any]
        summary_events,       # type: Dict[str, Any]
        account_data_events,  # type: List[Any]
        max_events=0          # type: int
    ):
        # type: (...) -> Tuple[RoomInfo, Optional[RoomInfo]]
        counter, state = _SyncResponse._get_room_events(
            state_events,
            max_events
        )

        unhandled_state = state_events[counter:]

        timeline_max = max_events - counter

        if timeline_max <= 0 and max_events > 0:
            timeline = Timeline(
                [],
                limited,
                prev_batch,
            )
            counter = 0
        else:
            counter, events = _SyncResponse._get_room_events(
                timeline_events, timeline_max
            )
            timeline = Timeline(events, limited, prev_batch)

        unhandled_timeline = Timeline(
            timeline_events[counter:],
            limited,
            prev_batch
        )

        ephemeral_event_list = _SyncResponse._get_ephemeral_events(
            ephemeral_events
        )

        unhandled_info = None

        if unhandled_timeline.events or unhandled_state:
            unhandled_info = RoomInfo(
                unhandled_timeline,
                unhandled_state,
                [],
                []
            )

        summary = RoomSummary(
            summary_events.get("m.invited_member_count", None),
            summary_events.get("m.joined_member_count", None),
            summary_events.get("m.heroes", [])
        )

        account_data = RoomInfo.parse_account_data(account_data_events)

        join_info = RoomInfo(
            timeline,
            state,
            ephemeral_event_list,
            account_data,
            summary,
        )

        return join_info, unhandled_info

    @staticmethod
    def _get_room_info(parsed_dict, max_events=0):
        # type: (Dict[Any, Any], int) -> Tuple[Rooms, Dict[str, RoomInfo]]
        joined_rooms = {
            key: None for key in parsed_dict["join"].keys()
        }  # type: Dict[str, Optional[RoomInfo]]
        invited_rooms = {}  # type: Dict[str, InviteInfo]
        left_rooms = {}     # type: Dict[str, RoomInfo]
        unhandled_rooms = {}

        for room_id, room_dict in parsed_dict["invite"].items():
            state = _SyncResponse._get_invite_state(room_dict["invite_state"])
            invite_info = InviteInfo(state)
            invited_rooms[room_id] = invite_info

        for room_id, room_dict in parsed_dict["leave"].items():
            _, state = _SyncResponse._get_state(room_dict["state"])
            _, timeline = _SyncResponse._get_timeline(room_dict["timeline"])
            leave_info = RoomInfo(timeline, state, [], [])
            left_rooms[room_id] = leave_info

        for room_id, room_dict in parsed_dict["join"].items():
            join_info, unhandled_info = _SyncResponse._get_join_info(
                room_dict["state"]["events"],
                room_dict["timeline"]["events"],
                room_dict["timeline"]["prev_batch"],
                room_dict["timeline"]["limited"],
                room_dict["ephemeral"]["events"],
                room_dict.get("summary", {}),
                room_dict["account_data"]["events"],
                max_events
            )

            if unhandled_info:
                unhandled_rooms[room_id] = unhandled_info

            joined_rooms[room_id] = join_info

        return Rooms(invited_rooms, joined_rooms, left_rooms), unhandled_rooms

    @classmethod
    @verify(Schemas.sync, SyncError, False)
    def from_dict(
        cls,
        parsed_dict,  # type: Dict[Any, Any]
        max_events=0,  # type: int
    ):
        # type: (...) -> Union[SyncType, ErrorResponse]
        to_device = cls._get_to_device(parsed_dict["to_device"])

        key_count_dict = parsed_dict["device_one_time_keys_count"]
        key_count = DeviceOneTimeKeyCount(
            key_count_dict["curve25519"],
            key_count_dict["signed_curve25519"]
        )

        devices = DeviceList(
            parsed_dict["device_lists"]["changed"],
            parsed_dict["device_lists"]["left"],
        )

        rooms, unhandled_rooms = _SyncResponse._get_room_info(
            parsed_dict["rooms"], max_events)

        if unhandled_rooms:
            return PartialSyncResponse(
                parsed_dict["next_batch"],
                rooms,
                key_count,
                devices,
                to_device,
                unhandled_rooms,
            )

        return SyncResponse(
            parsed_dict["next_batch"],
            rooms,
            key_count,
            devices,
            to_device,
        )


class SyncResponse(_SyncResponse):
    pass


@attr.s
class PartialSyncResponse(_SyncResponse):
    unhandled_rooms = attr.ib(type=Dict[str, RoomInfo])

    def next_part(self, max_events=0):
        # type: (int) -> SyncType
        unhandled_rooms = {}
        joined_rooms = {}
        for room_id, room_info in self.unhandled_rooms.items():
            join_info, unhandled_info = _SyncResponse._get_join_info(
                room_info.state,
                room_info.timeline.events,
                room_info.timeline.prev_batch,
                room_info.timeline.limited,
                [],
                {},
                [],
                max_events
            )

            if unhandled_info:
                unhandled_rooms[room_id] = unhandled_info

            joined_rooms[room_id] = join_info

        new_rooms = Rooms({}, joined_rooms, {})

        if unhandled_rooms:
            next_response = PartialSyncResponse(
                self.next_batch,
                new_rooms,
                self.device_key_count,
                DeviceList([], []),
                [],
                unhandled_rooms,
            )  # type: SyncType
        else:
            next_response = SyncResponse(
                self.next_batch,
                new_rooms,
                self.device_key_count,
                DeviceList([], []),
                [],
            )

        if self.uuid:
            next_response.uuid = self.uuid

        if self.start_time and self.end_time:
            next_response.start_time = self.start_time
            next_response.end_time = self.end_time

        return next_response


SyncType = Union[SyncResponse, PartialSyncResponse]
