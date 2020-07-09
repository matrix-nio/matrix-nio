# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
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

from builtins import bytes, super
from datetime import datetime, timedelta
from enum import Enum
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Union, Set
from uuid import uuid4, UUID

import olm
from future.moves.itertools import zip_longest

from ...api import Api
from ...events import (
    KeyVerificationEvent,
    KeyVerificationStart,
    RoomKeyVerificationRequest,
    RoomKeyVerificationStart,
    RoomKeyVerificationEvent,
    RoomKeyVerificationReady,
    KeyVerificationMac,
    RoomKeyVerificationMac,
    KeyVerificationKey,
    RoomKeyVerificationKey,
    RoomKeyVerificationCancel,
    KeyVerificationCancel,
    KeyVerificationAccept,
    RoomKeyVerificationAccept,
)
from ...responses import RoomSendResponse
from ...exceptions import LocalProtocolError

from ..sessions import OlmAccount
from ...event_builders import ToDeviceMessage, RoomEvent
from ...store import MatrixStore
from ..device import OlmDevice
from .. import DeviceStore, logger
from ..user_identities import UserIdentity


def get_verification_id(
    event: Union[RoomKeyVerificationEvent, KeyVerificationEvent]
) -> str:
    if isinstance(event, KeyVerificationEvent):
        return event.transaction_id
    else:
        return event.relates_to


class SasState(Enum):
    """Short Authentication String enum.

    This enum tracks the current state of our verification process.
    """

    created = 2
    started = 3
    accepted = 4
    key_received = 5
    mac_received = 6
    canceled = 7


class Sas(olm.Sas):
    """Matrix Short Authentication String class.

    This class implements a state machine to handle device verification using
    short authentication strings.

    Attributes:
        we_started_it (bool): Is true if the verification process was started
            by us, otherwise false.
        sas_accepted (bool): Is true if we accepted that the short
            authentication string matches on both devices.
        verified_devices(List[str]): The list of device ids that were verified
            during the verification process.

    Args:
        own_user (str): The user id of our own user.
        own_device (str): The device id of our own user.
        own_fp_key (str): The fingerprint key of our own device that will
            be verified by the other client.
        other_olm_device (OlmDevice): The OlmDevice which we would like to
            verify.
        verification_flow_id (str, optional): A string that will uniquely
            identify this verification process. A random and unique string will
            be generated if one isn't provided. If the verification process is
            happening inside a room, this will be the event id of the event
            that requested the verification to start.
        short_auth_string (List[str], optional): A list of valid short
            authentication methods that the client would like to allow for this
            authentication session. By default the 'emoji' and 'decimal'
            methods are allowed.
        room (str, optional): If the verification is happening inside of a room
            a room id should be given here. This is None if the verification is
            happening using to-device messages.
    """

    _sas_method_v1 = "m.sas.v1"
    _key_agreement_v2 = "curve25519-hkdf-sha256"
    _key_agreeemnt_protocols = [_key_agreement_v2]
    _hash_v1 = "sha256"
    _mac_normal = "hkdf-hmac-sha256"
    _mac_old = "hmac-sha256"
    _mac_v1 = [_mac_normal, _mac_old]
    _strings_v1 = ["emoji", "decimal"]

    _user_cancel_error = ("m.user", "Canceled by user")
    _timeout_error = ("m.timeout", "Timed out")
    _txid_error = ("m.unknown_transaction", "Unknown transaction")
    _unknonw_method_error = ("m.unknown_method", "Unknown method")
    _unexpected_message_error = ("m.unexpected_message", "Unexpected message")
    _key_mismatch_error = ("m.key_mismatch", "Key mismatch")
    _user_mismatch_error = ("m.user_error", "User mismatch")
    _invalid_message_error = ("m.invalid_message", "Invalid message")
    _commitment_mismatch_error = (
        "m.mismatched_commitment",
        "Mismatched commitment",
    )
    _sas_mismatch_error = (
        "m.mismatched_sas",
        "Mismatched short authentication string",
    )

    _max_age = timedelta(minutes=5)
    _max_event_timeout = timedelta(minutes=1)

    emoji = [
        ("🐶", "Dog"),
        ("🐱", "Cat"),
        ("🦁", "Lion"),
        ("🐎", "Horse"),
        ("🦄", "Unicorn"),
        ("🐷", "Pig"),
        ("🐘", "Elephant"),
        ("🐰", "Rabbit"),
        ("🐼", "Panda"),
        ("🐓", "Rooster"),
        ("🐧", "Penguin"),
        ("🐢", "Turtle"),
        ("🐟", "Fish"),
        ("🐙", "Octopus"),
        ("🦋", "Butterfly"),
        ("🌷", "Flower"),
        ("🌳", "Tree"),
        ("🌵", "Cactus"),
        ("🍄", "Mushroom"),
        ("🌏", "Globe"),
        ("🌙", "Moon"),
        ("☁️", "Cloud"),
        ("🔥", "Fire"),
        ("🍌", "Banana"),
        ("🍎", "Apple"),
        ("🍓", "Strawberry"),
        ("🌽", "Corn"),
        ("🍕", "Pizza"),
        ("🎂", "Cake"),
        ("❤️", "Heart"),
        ("😀", "Smiley"),
        ("🤖", "Robot"),
        ("🎩", "Hat"),
        ("👓", "Glasses"),
        ("🔧", "Wrench"),
        ("🎅", "Santa"),
        ("👍", "Thumbs up"),
        ("☂️", "Umbrella"),
        ("⌛", "Hourglass"),
        ("⏰", "Clock"),
        ("🎁", "Gift"),
        ("💡", "Light Bulb"),
        ("📕", "Book"),
        ("✏️", "Pencil"),
        ("📎", "Paperclip"),
        ("✂️", "Scissors"),
        ("🔒", "Lock"),
        ("🔑", "Key"),
        ("🔨", "Hammer"),
        ("☎️", "Telephone"),
        ("🏁", "Flag"),
        ("🚂", "Train"),
        ("🚲", "Bicycle"),
        ("✈️", "Airplane"),
        ("🚀", "Rocket"),
        ("🏆", "Trophy"),
        ("⚽", "Ball"),
        ("🎸", "Guitar"),
        ("🎺", "Trumpet"),
        ("🔔", "Bell"),
        ("⚓", "Anchor"),
        ("🎧", "Headphones"),
        ("📁", "Folder"),
        ("📌", "Pin"),
    ]

    def __init__(
        self,
        own_user: str,
        own_device: str,
        own_fp_key: str,
        other_user_id: str,
        other_olm_device: OlmDevice,
        verification_flow_id: str = None,
        short_auth_string: Optional[List[str]] = None,
        mac_methods: Optional[List[str]] = None,
        room_id: Optional[str] = None,
    ):
        self.own_user = own_user
        self.own_device = own_device
        self.own_fp_key = own_fp_key
        self.other_user_id = other_user_id

        self.other_olm_device = other_olm_device

        self.verification_flow_id = verification_flow_id or str(uuid4())

        self.short_auth_string = short_auth_string or ["emoji", "decimal"]
        self.mac_methods = mac_methods or Sas._mac_v1
        self.room_id = room_id
        self.chosen_mac_method = ""
        self.key_agreement_protocols = Sas._key_agreeemnt_protocols
        self.chosen_key_agreement: Optional[str] = None
        self.state = SasState.created
        self.we_started_it = True
        self.sas_accepted = False
        self.commitment = None
        self.cancel_reason = ""
        self.cancel_code = ""

        self.their_sas_key: Optional[str] = None

        self.verified_devices: List[str] = []

        self.creation_time = datetime.now()
        self._last_event_time = self.creation_time
        super().__init__()

    @classmethod
    def from_key_verification_start(
        cls,
        own_user: str,
        own_device: str,
        own_fp_key: str,
        other_olm_device: OlmDevice,
        event: Union[RoomKeyVerificationStart, KeyVerificationStart],
    ) -> "Sas":
        """Create a SAS object from a KeyVerificationStart event.

        Args:
            own_user (str): The user id of our own user.
            own_device (str): The device id of our own user.
            own_fp_key (str): The fingerprint key of our own device that will
                be verified by the other client.
            other_olm_device (OlmDevice): The Olm device of the other user that
                should be verified.
            event (KeyVerificationStart): The event that we received from the
                other device to start the key verification process.

        """
        if isinstance(event, RoomKeyVerificationStart):
            room_id = event.room_id
        else:
            room_id = None

        obj = cls(
            own_user,
            own_device,
            own_fp_key,
            other_olm_device.user_id,
            other_olm_device,
            get_verification_id(event),
            event.short_authentication_string,
            event.message_authentication_codes,
            room_id=room_id,
        )
        obj.we_started_it = False
        obj.state = SasState.started

        string_content = Api.to_canonical_json(event.source["content"])
        obj.commitment = olm.sha256(obj.pubkey + string_content)
        obj.key_agreement_protocols = event.key_agreement_protocols

        obj._check_start(event)

        return obj

    def _check_start(self, event):
        if (
            Sas._sas_method_v1 != event.method
            or (Sas._key_agreement_v2 not in event.key_agreement_protocols)
            or Sas._hash_v1 not in event.hashes
            or (
                Sas._mac_normal not in event.message_authentication_codes
                and Sas._mac_old not in event.message_authentication_codes
            )
            or (
                "emoji" not in event.short_authentication_string
                and "decimal" not in event.short_authentication_string
            )
        ):
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._unknonw_method_error

    @property
    def canceled(self) -> bool:
        """Is the verification request canceled."""
        return self.state == SasState.canceled

    @property
    def timed_out(self) -> bool:
        """Did the verification process time out."""
        if self.verified or self.canceled:
            return False

        now = datetime.now()
        if (
            now - self.creation_time >= self._max_age
            or now - self._last_event_time >= self._max_event_timeout
        ):
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._timeout_error
            return True
        return False

    @property
    def verified(self) -> bool:
        """Is the device verified and the request done."""
        return self.state == SasState.mac_received and self.sas_accepted

    def set_their_pubkey(self, pubkey: str):
        self.their_sas_key = pubkey
        super().set_their_pubkey(pubkey)

    def accept_sas(self):
        """Accept the short authentication string."""
        if self.state == SasState.canceled:
            raise LocalProtocolError(
                "Key verification process was canceled "
                "can't accept short authentication "
                "string"
            )

        if not self.other_key_set:
            raise LocalProtocolError(
                "Other public key isn't set yet, can't "
                "generate nor accept a short "
                "authentication string."
            )
        self.sas_accepted = True

    def reject_sas(self):
        """Reject the authentication string."""
        if not self.other_key_set:
            raise LocalProtocolError(
                "Other public key isn't set yet, can't "
                "generate nor reject a short "
                "authentication string."
            )

        self.state = SasState.canceled
        self.cancel_code, self.cancel_reason = self._sas_mismatch_error

    def cancel(self):
        """Cancel the authentication process."""
        self.state = SasState.canceled
        self.cancel_code, self.cancel_reason = self._user_cancel_error

    def _check_commitment(self, key: str):
        assert self.commitment
        calculated_commitment = olm.sha256(
            key + Api.to_canonical_json(self.start_verification().content)
        )
        return self.commitment == calculated_commitment

    def _grouper(self, iterable, n, fillvalue=None):
        """Collect data into fixed-length chunks or blocks."""
        # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
        args = [iter(iterable)] * n
        return zip_longest(*args, fillvalue=fillvalue)

    @property
    def _extra_info_v2(self) -> str:
        device = self.other_olm_device
        tx_id = self.verification_flow_id

        assert self.their_sas_key

        our_info = f"{self.own_user}|{self.own_device}|{self.pubkey}"
        their_info = (
            f"{device.user_id}|{device.device_id}|{self.their_sas_key}"
        )

        if self.we_started_it:
            return (
                f"MATRIX_KEY_VERIFICATION_SAS|{our_info}|{their_info}|{tx_id}"
            )
        else:
            return (
                f"MATRIX_KEY_VERIFICATION_SAS|{their_info}|{our_info}|{tx_id}"
            )

    @property
    def _extra_info(self) -> str:
        if self.chosen_key_agreement == Sas._key_agreement_v2:
            return self._extra_info_v2

        raise ValueError(
            f"Unknown key agreement protocol {self.chosen_key_agreement}"
        )

    def get_emoji(self) -> List[Tuple[str, str]]:
        """Get the emoji short authentication string.

        Returns a list of tuples that contain the emoji and the description of
        the emoji of the short authentication string.
        """
        return self._generate_emoji(self._extra_info)

    def get_decimals(self) -> Tuple[int, ...]:
        """Get the decimal short authentication string.

        Returns a tuple that contains three 4 digit integer numbers that
        represent the short authentication string.
        """
        return self._generate_decimals(self._extra_info)

    def _generate_emoji(self, extra_info: str) -> List[Tuple[str, str]]:
        """Create a list of emojies from our shared secret."""
        generated_bytes = self.generate_bytes(extra_info, 6)
        number = "".join([format(x, "08b") for x in bytes(generated_bytes)])
        return [
            self.emoji[int(x, 2)]
            for x in map("".join, list(self._grouper(number[:42], 6)))
        ]

    def _generate_decimals(self, extra_info: str) -> Tuple[int, ...]:
        """Create a decimal number from our shared secret."""
        generated_bytes = self.generate_bytes(extra_info, 5)
        number = "".join([format(x, "08b") for x in bytes(generated_bytes)])
        return tuple(
            int(x, 2) + 1000
            for x in map("".join, list(self._grouper(number[:-1], 13)))
        )

    def start_verification(self) -> Union[RoomEvent, ToDeviceMessage]:
        """Create a content dictionary to start the verification."""
        if not self.we_started_it:
            raise LocalProtocolError(
                "Verification was not started by us, "
                "can't send start verification message."
            )

        if self.state == SasState.canceled:
            raise LocalProtocolError(
                "SAS verification was canceled, "
                "can't send start verification message."
            )

        content: Dict[str, Any] = {
            "from_device": self.own_device,
            "method": self._sas_method_v1,
            "key_agreement_protocols": Sas._key_agreeemnt_protocols,
            "hashes": [self._hash_v1],
            "message_authentication_codes": self._mac_v1,
            "short_authentication_string": self._strings_v1,
        }

        event_type = "m.key.verification.start"

        if self.room_id:
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": self.verification_flow_id,
            }

            return RoomEvent(self.room_id, event_type, content)
        else:
            content["transaction_id"] = self.verification_flow_id
            return ToDeviceMessage(
                event_type,
                self.other_olm_device.user_id,
                self.other_olm_device.id,
                content,
            )

    def accept_verification(self) -> Union[RoomEvent, ToDeviceMessage]:
        """Create a content dictionary to accept the verification offer."""
        if self.we_started_it:
            raise LocalProtocolError(
                "Verification was started by us, can't accept offer."
            )

        if self.state == SasState.canceled:
            raise LocalProtocolError(
                "SAS verification was canceled, can't accept offer."
            )

        sas_methods = []

        if "emoji" in self.short_auth_string:
            sas_methods.append("emoji")

        if "decimal" in self.short_auth_string:
            sas_methods.append("decimal")

        if self._mac_normal in self.mac_methods:
            self.chosen_mac_method = self._mac_normal
        else:
            self.chosen_mac_method = self._mac_old

        self.chosen_key_agreement = Sas._key_agreement_v2

        content: Dict[str, Any] = {
            "key_agreement_protocol": self.chosen_key_agreement,
            "hash": self._hash_v1,
            "message_authentication_code": self.chosen_mac_method,
            "short_authentication_string": sas_methods,
            "commitment": self.commitment,
        }

        event_type = "m.key.verification.accept"

        if self.room_id:
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": self.verification_flow_id,
            }

            return RoomEvent(self.room_id, event_type, content)
        else:
            content["transaction_id"] = self.verification_flow_id
            return ToDeviceMessage(
                event_type,
                self.other_olm_device.user_id,
                self.other_olm_device.id,
                content,
            )

    def share_key(self) -> Union[RoomEvent, ToDeviceMessage]:
        """Create a dictionary containing our public key."""
        if self.state == SasState.canceled:
            raise LocalProtocolError(
                "SAS verification was canceled, can't " "share our public key."
            )

        content = {"key": self.pubkey}

        event_type = "m.key.verification.key"

        if self.room_id:
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": self.verification_flow_id,
            }

            return RoomEvent(self.room_id, event_type, content)
        else:
            content["transaction_id"] = self.verification_flow_id
            return ToDeviceMessage(
                event_type,
                self.other_olm_device.user_id,
                self.other_olm_device.id,
                content,
            )

    def get_mac(self) -> Union[RoomEvent, ToDeviceMessage]:
        """Create a dictionary containing our MAC."""
        if not self.sas_accepted:
            raise LocalProtocolError("SAS string wasn't yet accepted")

        if self.state == SasState.canceled:
            raise LocalProtocolError(
                "SAS verification was canceled, can't " "generate MAC."
            )

        key_id = "ed25519:{}".format(self.own_device)

        assert self.chosen_mac_method
        if self.chosen_mac_method == self._mac_normal:
            calculate_mac = self.calculate_mac
        elif self.chosen_mac_method == self._mac_old:
            calculate_mac = self.calculate_mac_long_kdf

        info = (
            "MATRIX_KEY_VERIFICATION_MAC"
            "{first_user}{first_device}"
            "{second_user}{second_device}{verification_flow_id}".format(
                first_user=self.own_user,
                first_device=self.own_device,
                second_user=self.other_olm_device.user_id,
                second_device=self.other_olm_device.id,
                verification_flow_id=self.verification_flow_id,
            )
        )

        mac = {key_id: calculate_mac(self.own_fp_key, info + key_id)}

        content = {
            "mac": mac,
            "keys": calculate_mac(key_id, info + "KEY_IDS"),
        }

        event_type = "m.key.verification.mac"

        if self.room_id:
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": self.verification_flow_id,
            }

            return RoomEvent(self.room_id, event_type, content)
        else:
            content["transaction_id"] = self.verification_flow_id
            return ToDeviceMessage(
                event_type,
                self.other_olm_device.user_id,
                self.other_olm_device.id,
                content,
            )

    def get_cancellation(self) -> Union[RoomEvent, ToDeviceMessage]:
        """Create a dictionary containing our verification cancellation."""
        if self.state != SasState.canceled:
            raise LocalProtocolError("Sas process isn't canceled.")

        assert self.cancel_code
        assert self.cancel_reason

        content: Dict[str, Any] = {
            "code": self.cancel_code,
            "reason": self.cancel_reason,
        }

        event_type = "m.key.verification.cancel"

        if self.room_id:
            content["m.relates_to"] = {
                "rel_type": "m.reference",
                "event_id": self.verification_flow_id,
            }

            return RoomEvent(self.room_id, event_type, content)
        else:
            content["transaction_id"] = self.verification_flow_id
            return ToDeviceMessage(
                event_type,
                self.other_olm_device.user_id,
                self.other_olm_device.id,
                content,
            )

    def _event_ok(
        self, event: Union[RoomKeyVerificationEvent, KeyVerificationEvent]
    ):
        if self.state == SasState.canceled:
            return False

        verification_flow_id: str = get_verification_id(event)

        if verification_flow_id != self.verification_flow_id:
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._txid_error
            return False

        if self.other_user_id != event.sender:
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._user_mismatch_error
            return False

        return True

    def receive_start_event(self, event):
        if not self._event_ok(event):
            return

        if (
            self.state != SasState.ready
            and self.state != SasState.created
            and self.state != SasState.request
        ):
            self.state = SasState.canceled
            (
                self.cancel_code,
                self.cancel_reason,
            ) = Sas._unexpected_message_error
            return

        if event.method != Sas._sas_method_v1:
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._unknonw_method_error
            return

        self.we_started_it = False
        self.state = SasState.started

        string_content = Api.to_canonical_json(event.source["content"])
        self.commitment = olm.sha256(self.pubkey + string_content)
        self.key_agreement_protocols = event.key_agreement_protocols

        self._check_start(event)

        return

    def receive_accept_event(self, event):
        """Receive a KeyVerificationAccept event."""
        if not self._event_ok(event):
            return

        if self.state != SasState.created:
            self.state = SasState.canceled
            (
                self.cancel_code,
                self.cancel_reason,
            ) = Sas._unexpected_message_error
            return

        if (
            event.key_agreement_protocol not in Sas._key_agreeemnt_protocols
            or event.hash != Sas._hash_v1
            or event.message_authentication_code not in Sas._mac_v1
            or (
                "emoji" not in event.short_authentication_string
                and "decimal" not in event.short_authentication_string
            )
        ):
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = Sas._unknonw_method_error
            return

        self.commitment = event.commitment
        self.chosen_mac_method = event.message_authentication_code
        self.chosen_key_agreement = event.key_agreement_protocol
        self.short_auth_string = event.short_authentication_string
        self.state = SasState.accepted

    def receive_key_event(self, event):
        """Receive a KeyVerificationKey event."""
        if self.other_key_set:
            self.state = SasState.canceled
            (
                self.cancel_code,
                self.cancel_reason,
            ) = self._unexpected_message_error
            return

        if not self._event_ok(event):
            return

        if self.we_started_it:
            if not self._check_commitment(event.key):
                self.state = SasState.canceled
                (
                    self.cancel_code,
                    self.cancel_reason,
                ) = self._commitment_mismatch_error
                return

        self.set_their_pubkey(event.key)
        self.state = SasState.key_received

    def receive_mac_event(self, event):
        """Receive a KeyVerificationMac event.

        Args:
            event (KeyVerificationMac): The MAC event that was received for
                this SAS session.

        """
        if self.verified:
            return

        if not self._event_ok(event):
            return

        if self.state != SasState.key_received:
            self.state = SasState.canceled
            (
                self.cancel_code,
                self.cancel_reason,
            ) = Sas._unexpected_message_error
            return

        info = (
            "MATRIX_KEY_VERIFICATION_MAC"
            "{first_user}{first_device}"
            "{second_user}{second_device}{verification_flow_id}".format(
                first_user=self.other_olm_device.user_id,
                first_device=self.other_olm_device.id,
                second_user=self.own_user,
                second_device=self.own_device,
                verification_flow_id=self.verification_flow_id,
            )
        )

        key_ids = ",".join(sorted(event.mac.keys()))

        assert self.chosen_mac_method

        if self.chosen_mac_method == self._mac_normal:
            calculate_mac = self.calculate_mac
        elif self.chosen_mac_method == self._mac_old:
            calculate_mac = self.calculate_mac_long_kdf

        if event.keys != calculate_mac(key_ids, info + "KEY_IDS"):
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._key_mismatch_error
            return

        for key_id, key_mac in event.mac.items():
            try:
                key_type, device_id = key_id.split(":", 2)
            except ValueError:
                self.state = SasState.canceled
                (
                    self.cancel_code,
                    self.cancel_reason,
                ) = self._invalid_message_error
                return

            if key_type != "ed25519":
                continue

            if device_id != self.other_olm_device.id:
                continue

            other_fp_key = self.other_olm_device.ed25519

            if key_mac != calculate_mac(other_fp_key, info + key_id):
                self.state = SasState.canceled
                self.cancel_code, self.cancel_reason = self._key_mismatch_error
                return

            self.verified_devices.append(device_id)

        if not self.verified_devices:
            self.state = SasState.canceled
            self.cancel_code, self.cancel_reason = self._key_mismatch_error

        self.state = SasState.mac_received


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
        own_user_identity: UserIdentity,
        other_user_identity: UserIdentity,
        room_id: str,
        methods: List[str] = None,
    ):
        self.own_user = own_user
        self.own_device = own_device
        self.own_fp_key = own_fp_key
        self.room_id = room_id
        self.own_user_identity = own_user_identity
        self.other_user_identity = other_user_identity
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
        own_user_identity: UserIdentity,
        other_user_identity: UserIdentity,
        event: RoomKeyVerificationRequest,
    ):
        assert event.room_id
        # TODO check
        obj = cls(
            own_user,
            own_device,
            own_fp_key,
            own_user_identity,
            other_user_identity,
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
            "to": self.other_user_identity.user_id,
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
            "to": self.other_user_identity.user_id,
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


class VerificationMachine:
    _max_sas_life = timedelta(minutes=20)

    def __init__(
        self,
        account: OlmAccount,
        user_id: str,
        device_id: str,
        store: MatrixStore,
        device_store: DeviceStore,
        cross_signing_store: Dict[str, UserIdentity],
        outgouing_to_device: List[ToDeviceMessage],
        users_for_query: Set[str],
    ):
        self.user_id: str = user_id
        self.device_id: str = device_id
        self.account: OlmAccount = account

        self.store = store

        # A store holding all the Olm devices of differing users we know about.
        self.device_store: DeviceStore = device_store

        # A store holding all the cross signing u ser identities.
        self.cross_signing_store: Dict[str, UserIdentity] = cross_signing_store

        # A mapping from the user to a verification request
        self.verification_requests: Dict[str, VerificationRequest] = dict()

        # A mapping from a verification id to a Sas key verification object.
        # The verification id uniquely identifies the key verification session.
        self.key_verifications: Dict[str, Sas] = dict()

        # A list of to-device messages that need to be sent to the homeserver
        # by the client. This will get populated by common to-device messages
        # for key-requests, interactive device verification and Olm session
        # unwedging.
        self.outgoing_to_device_messages: List[
            ToDeviceMessage
        ] = outgouing_to_device

        self.users_for_key_query: Set[str] = users_for_query

        # Alist of room messages that need to be sent to the given room. This
        # will get populated by room messages for interactive device
        # verification that happens inside a room.
        self.outgoing_room_messages: OrderedDict[
            Union[str, UUID], RoomEvent
        ] = OrderedDict()

    def clear_verifications(self):
        """Remove canceled or done key verifications from our cache.

        Returns a list of events that need to be added to the to-device event
        stream of our caller.

        """
        acitve_sas = dict()
        events = []

        now = datetime.now()

        for verification_flow_id, sas in self.key_verifications.items():
            if sas.timed_out:
                message = sas.get_cancellation()
                self.outgoing_to_device_messages.append(message)
                cancel_event = {
                    "sender": self.user_id,
                    "content": message.content,
                }
                events.append(KeyVerificationCancel.from_dict(cancel_event))
                continue
            elif sas.canceled or sas.verified:
                if now - sas.creation_time > self._max_sas_life:
                    continue
                acitve_sas[verification_flow_id] = sas
            else:
                acitve_sas[verification_flow_id] = sas

        self.key_verifications = acitve_sas

        return events

    def verify_device(self, device: OlmDevice) -> bool:
        return self.store.verify_device(device)

    def create_sas(
        self, olm_device: OlmDevice
    ) -> Union[ToDeviceMessage, RoomEvent]:
        sas = Sas(
            self.user_id,
            self.device_id,
            self.account.identity_keys["ed25519"],
            olm_device.user_id,
            olm_device,
        )
        self.key_verifications[sas.verification_flow_id] = sas

        return sas.start_verification()

    def get_active_sas(
        self, user_id: str, device_id: str = None
    ) -> Optional[Sas]:
        """Find a non-canceled SAS verification object for the provided user.

        Args:
            user_id (str): The user for which we should find a SAS verification
                object.
            device_id (str, optional): The device_id for which we should find
                the SAS verification object. If not given the newest SAS
                verification object for the given user will be returned.

        Returns the object if it's found, otherwise None.
        """
        verifications = [
            x for x in self.key_verifications.values() if not x.canceled
        ]

        for sas in sorted(
            verifications, key=lambda x: x.creation_time, reverse=True
        ):
            if (
                user_id == sas.other_user_id
                and device_id == sas.other_olm_device.device_id
            ):
                return sas

        return None

    def store_verification_message(
        self, message: Union[ToDeviceMessage, RoomEvent]
    ):
        if isinstance(message, ToDeviceMessage):
            self.outgoing_to_device_messages.append(message)
        else:
            self.outgoing_room_messages[message.transaction_id] = message

    def handle_verification_request(self, event: RoomKeyVerificationRequest):
        logger.info(
            f"Received a verification request from {event.sender} "
            f"{event.from_device}"
        )

        own_user_identity = self.cross_signing_store.get(self.user_id)
        other_user_identity = self.cross_signing_store.get(event.sender)

        request = VerificationRequest.from_request_event(
            self.user_id,
            self.device_id,
            self.account.identity_keys["ed25519"],
            own_user_identity,
            other_user_identity,
            event,
        )

        self.verification_requests[event.sender] = request

    def handle_start_events(
        self, event: Union[KeyVerificationStart, RoomKeyVerificationStart]
    ):
        logger.info(
            "Received key verification start event from "
            "{} {} {}".format(
                event.sender, event.from_device, get_verification_id(event)
            )
        )

        try:
            device = self.device_store[event.sender][event.from_device]
        except KeyError:
            logger.warn(
                "Received key verification event from unknown "
                "device: {} {}".format(event.sender, event.from_device)
            )
            self.users_for_key_query.add(event.sender)
            return

        new_sas = Sas.from_key_verification_start(
            self.user_id,
            self.device_id,
            self.account.identity_keys["ed25519"],
            device,
            event,
        )

        if new_sas.canceled:
            logger.warn(
                "Received malformed key verification event from "
                "{} {}".format(event.sender, event.from_device)
            )
            message = new_sas.get_cancellation()
            self.store_verification_message(message)

        else:
            old_sas = self.get_active_sas(event.sender, event.from_device)

            if old_sas:
                logger.info(
                    "Found an active verification process for the "
                    "same user/device combination, "
                    "canceling the old one. "
                    "Old Sas: {} {} {}".format(
                        event.sender,
                        event.from_device,
                        old_sas.verification_flow_id,
                    )
                )
                old_sas.cancel()
                cancel_message = old_sas.get_cancellation()

                self.store_verification_message(cancel_message)

            logger.info(
                "Successfully started key verification with "
                "{} {} {}".format(
                    event.sender,
                    event.from_device,
                    new_sas.verification_flow_id,
                )
            )
            self.key_verifications[new_sas.verification_flow_id] = new_sas

            # If this was started with a verification request the
            # verification process is already accepted by the user so send
            # out an accept message

            try:
                request = self.verification_requests.pop(event.sender)
                if (
                    request.verification_flow_id
                    == new_sas.verification_flow_id
                ):
                    self.store_verification_message(
                        new_sas.accept_verification()
                    )
            except KeyError:
                pass

    def handle_accept_event(
        self,
        sas: Sas,
        event: Union[RoomKeyVerificationAccept, KeyVerificationAccept],
    ):
        sas.receive_accept_event(event)

        if sas.canceled:
            message = sas.get_cancellation()
        else:
            logger.info(
                "Received a key verification accept event "
                "from {} {}, sharing keys {}".format(
                    event.sender,
                    sas.other_olm_device.id,
                    sas.verification_flow_id,
                )
            )
            message = sas.share_key()

        self.store_verification_message(message)

    def handle_cancel_event(
        self,
        sas: Sas,
        event: Union[KeyVerificationCancel, RoomKeyVerificationCancel],
    ):
        logger.info(
            "Received a key verification cancellation "
            "from {} {}. Canceling verification {}.".format(
                event.sender,
                sas.other_olm_device.id,
                sas.verification_flow_id,
            )
        )
        sas = self.key_verifications.pop(get_verification_id(event))

        if sas:
            sas.cancel()

    def handle_key_event(
        self,
        sas: Sas,
        event: Union[RoomKeyVerificationKey, KeyVerificationKey],
    ):
        sas.receive_key_event(event)

        outgoing_message: Optional[Union[RoomEvent, ToDeviceMessage]] = None

        if sas.canceled:
            outgoing_message = sas.get_cancellation()
        else:
            logger.info(
                "Received a key verification pubkey "
                "from {} {} {}.".format(
                    event.sender,
                    sas.other_olm_device.id,
                    sas.verification_flow_id,
                )
            )

        if not sas.we_started_it and not sas.canceled:
            outgoing_message = sas.share_key()

        if outgoing_message:
            self.store_verification_message(outgoing_message)

    def handle_mac_event(
        self,
        sas: Sas,
        event: Union[KeyVerificationMac, RoomKeyVerificationMac],
    ):
        sas.receive_mac_event(event)

        if sas.canceled:
            cancel_message = sas.get_cancellation()
            self.store_verification_message(cancel_message)

            return

        logger.info(
            "Received a valid key verification MAC "
            "from {} {} {}.".format(
                event.sender,
                sas.other_olm_device.id,
                get_verification_id(event),
            )
        )

        if sas.verified:
            logger.info(
                "Interactive key verification successful, "
                "verifying device {} of user {} {}.".format(
                    sas.other_olm_device.id,
                    event.sender,
                    get_verification_id(event),
                )
            )
            device = sas.other_olm_device
            assert device
            self.verify_device(device)

    def handle_key_verification(
        self,
        event: Union[
            KeyVerificationEvent,
            RoomKeyVerificationEvent,
            RoomKeyVerificationRequest,
        ],
    ):
        """Receive key verification events."""
        if isinstance(event, RoomKeyVerificationRequest):
            self.handle_verification_request(event)

        elif isinstance(
            event, (RoomKeyVerificationStart, KeyVerificationStart)
        ):
            self.handle_start_events(event)

        else:
            sas = self.key_verifications.get(get_verification_id(event))

            if not sas:
                logger.warn(
                    "Received key verification event with an unknown "
                    "id from {}".format(event.sender)
                )
                return

            if isinstance(
                event, (RoomKeyVerificationAccept, KeyVerificationAccept)
            ):
                self.handle_accept_event(sas, event)

            elif isinstance(
                event, (RoomKeyVerificationCancel, KeyVerificationCancel)
            ):
                self.handle_cancel_event(sas, event)

            elif isinstance(
                event, (KeyVerificationKey, RoomKeyVerificationKey)
            ):
                self.handle_key_event(sas, event)

            elif isinstance(
                event, (KeyVerificationMac, RoomKeyVerificationMac)
            ):
                self.handle_mac_event(sas, event)
