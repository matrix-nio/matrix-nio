# -*- coding: utf-8 -*-

# Copyright © 2020 Damir Jelić <poljar@termina.org.uk>
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

import attr
from typing import Dict

from ..event_builders import ToDeviceMessage, RoomKeyRequestMessage
from ..responses import RoomKeyRequestResponse

@attr.s
class OutgoingKeyRequest(object):
    """Key request that we sent out."""

    request_id = attr.ib(type=str)
    session_id = attr.ib(type=str)
    room_id = attr.ib(type=str)
    algorithm = attr.ib(type=str)

    @classmethod
    def from_response(cls, response):
        # type: (RoomKeyRequestResponse) -> OutgoingKeyRequest
        """Create a key request object from a RoomKeyRequestResponse."""
        return cls(
            response.request_id,
            response.session_id,
            response.room_id,
            response.algorithm
        )

    @classmethod
    def from_message(cls, message):
        # type: (RoomKeyRequestMessage) -> OutgoingKeyRequest
        """Create a key request object from a RoomKeyRequestMessage."""
        return cls(
            message.request_id,
            message.session_id,
            message.room_id,
            message.algorithm,
        )

    @classmethod
    def from_database(cls, row):
        """Create a key request object from a database row."""
        return cls.from_response(row)

    def as_cancellation(self, user_id, requesting_device_id):
        """Turn the key request into a cancellation to-device message."""
        content = {
            "action": "request_cancellation",
            "request_id": self.request_id,
            "requesting_device_id": requesting_device_id,
        }

        return ToDeviceMessage(
            "m.room_key_request",
            user_id,
            "*",
            content
        )
