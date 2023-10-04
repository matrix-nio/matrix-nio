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

"""nio common event type mixins

This module contains mixin classes for events that can be found in the
to-device part of a sync response or in a room timeline of a sync response.

"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class KeyVerificationEventMixin:
    """Base class for key verification events.

    Attributes:
        transaction_id (str): An opaque identifier for the verification
            process. Must be unique with respect to the devices involved.

    """

    transaction_id: str = field()


@dataclass
class KeyVerificationStartMixin:
    """Event signaling the start of a SAS key verification process.

    Attributes:
        from_device (str): The device ID which is initiating the process.
        method (str): The verification method to use.
        key_agreement_protocols (list): A list of strings specifying the
            key agreement protocols the sending device understands.
        hashes (list): A list of strings specifying the hash methods the
            sending device understands.
        message_authentication_codes (list): A list of strings specifying the
            message authentication codes that the sending device understands.
        short_authentication_string (list): A list of strings specifying the
            SAS methods the sending device (and the sending device's user)
            understands.

    """

    from_device: str = field()
    method: str = field()
    key_agreement_protocols: List[str] = field()
    hashes: List[str] = field()
    message_authentication_codes: List[str] = field()
    short_authentication_string: List[str] = field()


@dataclass
class KeyVerificationAcceptMixin:
    """Event signaling that the SAS verification start has been accepted.

    Attributes:
        commitment (str): The commitment value of the verification process.
        key_agreement_protocol (str): The key agreement protocol the device is
            choosing to use
        hash (str): A list of strings specifying the hash methods the
            sending device understands.
        message_authentication_code (str): The message authentication code the
            device is choosing to use.
        short_authentication_string (list): A list of strings specifying the
            SAS methods that can be used in the verification process.

    """

    commitment: str = field()
    key_agreement_protocol: str = field()
    hash: str = field()
    message_authentication_code: str = field()
    short_authentication_string: List[str] = field()


@dataclass
class KeyVerificationKeyMixin:
    """Event carrying a key verification key.

    After this event is received the short authentication string can be shown
    to the user.

    Attributes:
        key (str): The device's ephemeral public key, encoded as
            unpadded base64.

    """

    key: str = field()


@dataclass
class KeyVerificationMacMixin:
    """Event holding a message authentication code of the verification process.

    After this event is received the device that we are verifying will be
    marked as verified given that we have accepted the short authentication
    string as well.

    Attributes:
        mac (dict): A map of the key ID to the MAC of the key, using the
            algorithm in the verification process. The MAC is encoded as
            unpadded base64.
        keys (str): The MAC of the comma-separated, sorted, list of key IDs
            given in the mac property, encoded as unpadded base64.

    """

    mac: Dict[str, str] = field()
    keys: str = field()


@dataclass
class KeyVerificationCancelMixin:
    """Event signaling that a key verification process has been canceled.

    Attributes:
        code (str): The error code for why the process/request was canceled by
            the user.
        reason (str): A human readable description of the cancellation code.

    """

    code: str = field()
    reason: str = field()
