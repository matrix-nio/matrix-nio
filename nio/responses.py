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

from builtins import str, super
from typing import Any, Dict, List, NamedTuple, Optional, Union, Type, TypeVar

from datetime import datetime
from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .events import (
    Event,
    InviteEvent,
    PowerLevelsEvent,
    RedactedEvent,
    RoomAliasEvent,
    RoomEncryptionEvent,
    RoomMessage,
    RoomNameEvent,
    RoomTopicEvent,
    UnknownBadEvent,
    ToDeviceEvent,
)
from .log import logger_group
from .schemas import Schemas, validate_json

logger = Logger("nio.responses")
logger_group.add_logger(logger)


Rooms = NamedTuple(
    "Rooms", [("invite", dict), ("join", dict), ("leave", dict)]
)

DeviceOneTimeKeyCount = NamedTuple(
    "DeviceOneTimeKeyCount", [("curve25519", int), ("signed_curve25519", int)]
)

DeviceList = NamedTuple(
    "DeviceList", [("changed", list), ("left", list)]
)

Timeline = NamedTuple(
    "Timeline", [("events", list), ("limited", bool), ("prev_batch", str)]
)

InviteInfo = NamedTuple("InviteInfo", [("invite_state", list)])

RoomInfo = NamedTuple("RoomInfo", [("timeline", Timeline), ("state", list)])


class Device(object):
    def __init__(self, id, display_name, last_seen_ip, last_seen_date):
        # type(str, str, str, datetime) -> None
        self.id = id
        self.display_name = display_name
        self.last_seen_ip = last_seen_ip
        self.last_seen_date = last_seen_date

    @classmethod
    def from_dict(cls, parsed_dict):
        date = datetime.fromtimestamp(parsed_dict["last_seen_ts"] / 1000)
        return cls(
            parsed_dict["device_id"],
            parsed_dict["display_name"],
            parsed_dict["last_seen_ip"],
            date
        )


class Response(object):
    def __init__(self):
        self.uuid = ""
        self.start_time = None
        self.end_time = None

    @property
    def elapsed(self):
        if not self.start_time or not self.end_time:
            return 0
        return self.end_time - self.start_time


class ErrorResponse(Response):
    def __init__(self, message, code=""):
        # type: (str, Optional[str]) -> None
        super().__init__()
        self.message = message
        self.code = code

    def __str__(self):
        # type: () -> str
        return "Error: {}".format(self.message)

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> ErrorResponse
        try:
            validate_json(parsed_dict, Schemas.error)
        except (SchemaError, ValidationError):
            return cls("Unknown error")

        return cls(parsed_dict["error"], parsed_dict["errcode"])


class LoginResponse(Response):
    def __init__(self, user_id, device_id, access_token):
        # type: (str, str, str) -> None
        super().__init__()
        self.user_id = user_id
        self.device_id = device_id
        self.access_token = access_token

    def __str__(self):
        # type: () -> str
        return "Logged in as {}, device id: {}.".format(
            self.user_id, self.device_id
        )

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[LoginResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.login)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        return cls(
            parsed_dict["user_id"],
            parsed_dict["device_id"],
            parsed_dict["access_token"],
        )


class RoomEventIdResponse(Response):
    def __init__(self, event_id):
        super().__init__()
        self.event_id = event_id

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomEventIdResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.room_event_id)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        return cls(parsed_dict["event_id"])


class RoomSendResponse(RoomEventIdResponse):
    pass


class RoomPutStateResponse(RoomEventIdResponse):
    pass


class RoomRedactResponse(RoomEventIdResponse):
    pass


class EmptyResponse(Response):
    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[Any, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.empty)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        return cls()


class RoomKickResponse(EmptyResponse):
    pass


class RoomInviteResponse(EmptyResponse):
    pass


class ShareGroupSessionResponse(EmptyResponse):
    def __init__(self):
        self.room_id = None  # type: Optional[str]
        super().__init__()

    @classmethod
    def from_dict(
        cls,
        parsed_dict  # type: Dict[Any, Any]
    ):
        # type: (...) -> Union[ShareGroupSessionResponse, ErrorResponse]
        object = super().from_dict(parsed_dict)
        return object


class RoomMessagesResponse(Response):
    def __init__(self, chunk, start, end):
        # type: (List[Union[Event, UnknownBadEvent]], str, str) -> None
        self.chunk = chunk
        self.start = start
        self.end = end

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomMessagesResponse, ErrorResponse]
        chunk = []  # type: List[Union[Event, UnknownBadEvent]]
        try:
            validate_json(parsed_dict, Schemas.room_messages)
            chunk = (SyncResponse._get_room_events(parsed_dict["chunk"]))
        except (SchemaError, ValidationError) as e:
            print(str(e))
            return ErrorResponse.from_dict(parsed_dict)

        return cls(chunk, parsed_dict["start"], parsed_dict["end"])


class RoomIdResponse(Response):
    def __init__(self, room_id):
        super().__init__()
        self.room_id = room_id

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[RoomIdResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.room_id)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        return cls(parsed_dict["room_id"])


class JoinResponse(RoomIdResponse):
    pass


class RoomLeaveResponse(EmptyResponse):
    pass


class KeysUploadResponse(Response):
    def __init__(self, curve25519_count, signed_curve25519_count):
        # type: (int, int) -> None
        self.curve25519_count = curve25519_count
        self.signed_curve25519_count = signed_curve25519_count

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[KeysUploadResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.keys_upload)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        counts = parsed_dict["one_time_key_counts"]

        return cls(counts["curve25519"], counts["signed_curve25519"])


class KeysQueryResponse(Response):
    def __init__(self, device_keys, failures):
        # type: (Dict[Any, Any], Dict[Any, Any]) -> None
        self.device_keys = device_keys
        self.failures = failures

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[KeysQueryResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.keys_query)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        device_keys = parsed_dict["device_keys"]
        failures = parsed_dict["failures"]

        return cls(device_keys, failures)


class KeysClaimResponse(Response):
    def __init__(self, one_time_keys, failures):
        # type: (Dict[Any, Any], Dict[Any, Any]) -> None
        self.one_time_keys = one_time_keys
        self.failures = failures
        self.room_id = None  # type: Optional[str]

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[KeysClaimResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.keys_claim)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        one_time_keys = parsed_dict["one_time_keys"]
        failures = parsed_dict["failures"]

        return cls(one_time_keys, failures)


class DevicesResponse(Response):
    def __init__(self, devices):
        # type: (List[Device]) -> None
        self.devices = devices

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[DevicesResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.devices)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        devices = []
        for device_dict in parsed_dict["devices"]:
            try:
                device = Device.from_dict(device_dict)
            except ValueError:
                continue
            devices.append(device)

        return cls(devices)


class SyncResponse(Response):
    def __init__(
        self,
        next_batch,        # type: str
        rooms,             # type: Rooms
        device_key_count,  # type: DeviceOneTimeKeyCount
        device_list,       # type: DeviceList
        to_device_events,  # type: List[ToDeviceEvent]
        partial            # type: bool
    ):
        # type: (...) -> None
        super().__init__()
        self.next_batch = next_batch
        self.rooms = rooms
        self.device_key_count = device_key_count
        self.device_list = device_list
        self.to_device_events = to_device_events
        self.partial = partial

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
    def _get_event(event_dict, olm=None):
        pass

    @staticmethod
    def _get_room_events(parsed_dict, max_events=0):
        # type: (Dict[Any, Any], int) -> List[Union[Event, UnknownBadEvent]]
        events = []  # type: List[Union[Event, UnknownBadEvent]]

        for event_dict in parsed_dict:
            try:
                validate_json(event_dict, Schemas.room_event)
            except (SchemaError, ValidationError) as e:
                logger.error("Error validating event: {}".format(str(e)))
                events.append(UnknownBadEvent(event_dict))
                continue

            event = Event.parse_event(event_dict)

            if event:
                events.append(event)

        return events

    @staticmethod
    def _get_to_device(parsed_dict):
        # type: (Dict[Any, Any]) -> List[ToDeviceEvent]
        events = []  # type: List[ToDeviceEvent]
        for event_dict in parsed_dict["events"]:
            event = ToDeviceEvent.parse_event(event_dict)

            if isinstance(event, ToDeviceEvent):
                events.append(event)

        return events

    @staticmethod
    def _get_timeline(parsed_dict, max_events=0):
        # type: (Dict[Any, Any], int) -> Timeline
        validate_json(parsed_dict, Schemas.room_timeline)

        events = SyncResponse._get_room_events(
            parsed_dict["events"],
            max_events
        )

        return Timeline(
            events, parsed_dict["limited"], parsed_dict["prev_batch"]
        )

    @staticmethod
    def _get_state(parsed_dict, max_events=0):
        validate_json(parsed_dict, Schemas.room_state)
        events = SyncResponse._get_room_events(
            parsed_dict["events"],
            max_events
        )

        return events

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
    def _get_room_info(parsed_dict, max_events=0, olm=None):
        # type: (Dict[Any, Any], int, Any) -> Rooms
        joined_rooms = {
            key: None for key in parsed_dict["join"].keys()
        }  # type: Dict[str, Optional[RoomInfo]]
        invited_rooms = {}  # type: Dict[str, InviteInfo]
        left_rooms = {}  # type: Dict[str, RoomInfo]

        for room_id, room_dict in parsed_dict["invite"].items():
            state = SyncResponse._get_invite_state(room_dict["invite_state"])
            invite_info = InviteInfo(state)
            invited_rooms[room_id] = invite_info

        for room_id, room_dict in parsed_dict["leave"].items():
            state = SyncResponse._get_state(room_dict["state"])
            timeline = SyncResponse._get_timeline(room_dict["timeline"])
            leave_info = RoomInfo(timeline, state)
            left_rooms[room_id] = leave_info

        for room_id, room_dict in parsed_dict["join"].items():
            state = SyncResponse._get_state(room_dict["state"])
            timeline = SyncResponse._get_timeline(room_dict["timeline"])
            join_info = RoomInfo(timeline, state)
            joined_rooms[room_id] = join_info

        return Rooms(invited_rooms, joined_rooms, left_rooms)

    @classmethod
    def from_dict(
        cls,
        parsed_dict,  # type: Dict[Any, Any]
        max_events=0,  # type: int
        olm=None,  # type: Any
    ):
        # type: (...) -> Union[SyncResponse, ErrorResponse]
        partial = False

        try:
            logger.info("Validating sync response schema")
            validate_json(parsed_dict, Schemas.sync)
        except (SchemaError, ValidationError) as e:
            logger.error("Error validating sync response: " + str(e.message))
            return ErrorResponse.from_dict(parsed_dict)

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

        rooms = SyncResponse._get_room_info(
            parsed_dict["rooms"], max_events, olm
        )

        return cls(
            parsed_dict["next_batch"],
            rooms,
            key_count,
            devices,
            to_device,
            partial
        )
