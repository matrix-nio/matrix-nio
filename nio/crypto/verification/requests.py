# Copyright © 2020 The Matrix.org Foundation C.I.C.
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

from enum import Enum
from typing import Any, Dict, List, Optional

from .sas import Sas
from ..device import OlmDevice
from ..user_identities import UserIdentity
from ...responses import RoomSendResponse
from ...events import (
    RoomKeyVerificationRequest,
    RoomKeyVerificationReady,
)
from ...event_builders import RoomEvent


class VerificationRequestState(Enum):
    created = 0
    requested = 1
    ready = 2
    passive = 3


class VerificationRequest:
    def __init__(
        self,
        own_user: str,
        own_device: str,
        own_fp_key: str,
        other_user: str,
        room_id: str,
        methods: List[str] = None,
    ):
        self.own_user = own_user
        self.own_device = own_device
        self.own_fp_key = own_fp_key
        self.other_user = other_user
        self.room_id = room_id
        self.other_device_id: Optional[str] = None
        self.verification_flow_id: Optional[str] = None
        self.methods: List[str] = methods or [Sas._sas_method_v1]
        self.we_started = True

        self.state = VerificationRequestState.created

    @classmethod
    def from_request_event(
        cls,
        own_user: str,
        own_device: str,
        own_fp_key: str,
        event: RoomKeyVerificationRequest,
    ):
        assert event.room_id
        # TODO check
        obj = cls(
            own_user,
            own_device,
            own_fp_key,
            event.sender,
            event.room_id,
        )

        obj.other_device_id = event.from_device
        obj.verification_flow_id = event.event_id
        obj.we_started = False

        # If we don't support any of the methods, become passive.
        if Sas._sas_method_v1 in event.methods:
            obj.state = VerificationRequestState.requested
        else:
            obj.state = VerificationRequestState.passive
        return obj

    def receive_room_send_response(self, response: RoomSendResponse):
        self.verification_flow_id = response.event_id

    def get_request_message(self) -> RoomEvent:
        if self.state != VerificationRequestState.created:
            raise ValueError(
                "The verficiation request wasn't created by us, so we "
                "can't send out a verification request"
            )

        content: Dict[str, Any] = {
            "from_device": self.own_device,
            "msgtype": "m.key.verification.request",
            "methods": [Sas._sas_method_v1],
            "body": f"{self.own_user} is requesting to verify your key, "
            "but your client does not support in-chat key "
            "verification. You will need to use legacy key "
            "verification to verify keys.",
            "to": self.other_user,
        }

        event_type = "m.room.message"

        assert self.room_id
        return RoomEvent(self.room_id, event_type, content)

    def get_ready_message(self) -> RoomEvent:
        if self.state == VerificationRequestState.passive:
            raise ValueError(
                "The verficiation request does not support any method that we "
                "support, can't send out a verification ready message"
            )
        if self.state != VerificationRequestState.requested:
            raise ValueError(
                "The verficiation request was created by us, "
                "can't send out a verification ready message"
            )

        content: Dict[str, Any] = {
            "from_device": self.own_device,
            "methods": [Sas._sas_method_v1],
            "to": self.other_user,
        }

        content["m.relates_to"] = {
            "rel_type": "m.reference",
            "event_id": self.verification_flow_id,
        }

        event_type = "m.key.verification.ready"
        assert self.room_id
        return RoomEvent(self.room_id, event_type, content)

    def receive_ready_event(self, event: RoomKeyVerificationReady):
        if (
            event.sender == self.own_user
            and event.from_device != self.own_device
        ):
            self.state = VerificationRequestState.passive

        self.other_device_id = event.from_device
        self.state = VerificationRequestState.ready

    def into_sas_verification(self, other_device: OlmDevice) -> Sas:
        if other_device.device_id != self.other_device_id:
            raise ValueError(
                "The given device doesn't match the other users" "device id"
            )

        sas = Sas(
            self.own_user,
            self.own_device,
            self.own_fp_key,
            other_device.user_id,
            other_device,
            self.verification_flow_id,
            room_id=self.room_id,
        )
        sas.we_started_it = self.we_started

        return sas
