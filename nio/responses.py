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

from typing import *
from typing import NamedTuple

from jsonschema.exceptions import SchemaError, ValidationError
from logbook import Logger

from .log import logger_group
from .schemas import validate_json, Schemas
from .events import (
    RoomMessage,
    RedactedEvent,
    RoomAliasEvent,
    RoomNameEvent,
    RoomTopicEvent,
    RoomEncryptionEvent,
    PowerLevelsEvent
)

logger = Logger('nio.responses')
logger_group.add_logger(logger)


RoomInfo = NamedTuple("RoomInfo", [
    ("invite", dict),
    ("join", dict),
    ("leave", dict)
])

Timeline = NamedTuple(
    "Timeline",
    [
        ("events", list),
        ("limited", bool),
        ("prev_batch", str)
    ]
)

JoindedInfo = NamedTuple(
    "JoinedInfo",
    [
        ("timeline", Timeline),
        ("state", list),
    ]
)


class Response(object):
    pass


class ErrorResponse(Response):
    def __init__(self, message, code=""):
        # type: (str, Optional[str]) -> None
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
        self.user_id = user_id
        self.device_id = device_id
        self.access_token = access_token

    def __str__(self):
        # type: () -> str
        return "Logged in as {}, device id: {}.".format(
            self.user_id,
            self.device_id
        )

    @classmethod
    def from_dict(cls, parsed_dict):
        # type: (Dict[Any, Any]) -> Union[LoginResponse, ErrorResponse]
        try:
            validate_json(parsed_dict, Schemas.login)
        except (SchemaError, ValidationError):
            return ErrorResponse.from_dict(parsed_dict)

        return cls(parsed_dict["user_id"],
                   parsed_dict["device_id"],
                   parsed_dict["access_token"])


class SyncRepsponse(Response):
    def __init__(self, next_batch, rooms, partial):
        # type: (str, RoomInfo, bool) -> None
        self.next_batch = next_batch
        self.rooms = rooms
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
            self.next_batch,
            body
        )
        return string

    @staticmethod
    def _get_event(event_dict, olm=None):
        pass

    @staticmethod
    def _get_room_events(parsed_dict, max_events=0, olm=None):
        # type: (Dict[Any, Any], int, Any) -> List[Any]
        events = []  # type: List[Any]

        for event_dict in parsed_dict:
            try:
                validate_json(event_dict, Schemas.room_event)

                if "unsigned" in event_dict:
                    if "redacted_because" in event_dict["unsigned"]:
                        events.append(RedactedEvent.from_dict(event_dict))
                        continue

                if event_dict["type"] == "m.room.message":
                    # The transaction id will only be present for events that
                    # are send out from this client, since we print out our own
                    # messages as soon as we get a receive confirmation from
                    # the server we don't care about our own messages in a
                    # sync event. More info under:
                    # https://github.com/matrix-org/matrix-doc/blob/master/api/client-server/definitions/event.yaml#L53
                    if "transaction_id" in event_dict["unsigned"]:
                        continue
                    events.append(RoomMessage.from_dict(event_dict, olm))
                elif event_dict["type"] == "m.room.canonical_alias":
                    events.append(RoomAliasEvent.from_dict(event_dict))
                elif event_dict["type"] == "m.room.name":
                    events.append(RoomNameEvent.from_dict(event_dict))
                elif event_dict["type"] == "m.room.topic":
                    events.append(RoomTopicEvent.from_dict(event_dict))
                elif event_dict["type"] == "m.room.power_levels":
                    events.append(PowerLevelsEvent.from_dict(event_dict))
                elif event_dict["type"] == "m.room.encryption":
                    events.append(RoomEncryptionEvent.from_dict(event_dict))

            except (SchemaError, ValidationError) as e:
                print(e)
                pass

        return events

    @staticmethod
    def _get_timeline(parsed_dict, max_events=0, olm=None):
        # type: (Dict[Any, Any], int, Any) -> Timeline
        validate_json(parsed_dict, Schemas.room_timeline)

        events = SyncRepsponse._get_room_events(
            parsed_dict["events"],
            max_events,
            olm
        )

        return Timeline(
            events,
            parsed_dict["limited"],
            parsed_dict["prev_batch"]
        )

    @staticmethod
    def _get_state(parsed_dict, max_events=0, olm=None):
        validate_json(parsed_dict, Schemas.room_state)
        events = SyncRepsponse._get_room_events(
            parsed_dict["events"],
            max_events,
            olm
        )

        return events

    @staticmethod
    def _get_room_info(parsed_dict, max_events=0, olm=None):
        # type: (Dict[Any, Any], int, Any) -> RoomInfo
        joined_rooms = {
            key: None for key in parsed_dict["join"].keys()
        }  # type: Dict[str, Optional[JoindedInfo]]
        invited_rooms = {}  # type: Dict[str, Any]
        left_rooms = {}  # type: Dict[str, Any]

        for room_id, room_dict in parsed_dict["join"].items():
            state = SyncRepsponse._get_state(room_dict["state"])
            timeline = SyncRepsponse._get_timeline(room_dict["timeline"])
            info = JoindedInfo(
                timeline,
                state,
            )
            joined_rooms[room_id] = info

        return RoomInfo(invited_rooms, joined_rooms, left_rooms)

    @classmethod
    def from_dict(
        cls,
        parsed_dict,   # type: Dict[Any, Any]
        max_events=0,  # type: int
        olm=None       # type: Any
    ):
        # type: (...) -> Union[SyncRepsponse, ErrorResponse]
        partial = False

        try:
            logger.info("Validating sync response schema")
            validate_json(parsed_dict, Schemas.sync)
            rooms = SyncRepsponse._get_room_info(
                parsed_dict["rooms"],
                max_events,
                olm
            )
        except (SchemaError, ValidationError) as e:
            logger.error("Error validating sync response: " + str(e.message))
            return ErrorResponse.from_dict(parsed_dict)

        return cls(parsed_dict["next_batch"],
                   rooms, partial)
