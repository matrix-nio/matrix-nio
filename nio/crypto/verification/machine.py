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

from datetime import datetime, timedelta
from collections import OrderedDict
from typing import Dict, List, Optional, Union, Set
from uuid import UUID

from .sas import Sas, get_verification_id
from .requests import VerificationRequest

from ..user_identities import UserIdentity
from ..sessions import OlmAccount
from ...event_builders import ToDeviceMessage, RoomEvent
from ...store import MatrixStore
from ..device import OlmDevice
from .. import DeviceStore, logger

from ...events import (
    KeyVerificationEvent,
    KeyVerificationStart,
    RoomKeyVerificationRequest,
    RoomKeyVerificationStart,
    RoomKeyVerificationEvent,
    KeyVerificationMac,
    RoomKeyVerificationMac,
    KeyVerificationKey,
    RoomKeyVerificationKey,
    RoomKeyVerificationCancel,
    KeyVerificationCancel,
    KeyVerificationAccept,
    RoomKeyVerificationAccept,
)


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

        request = VerificationRequest.from_request_event(
            self.user_id,
            self.device_id,
            self.account.identity_keys["ed25519"],
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
        # Ignore our own events.
        if event.sender == self.user_id:
            return

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
