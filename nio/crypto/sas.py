# -*- coding: utf-8 -*-

# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
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

from enum import Enum
from builtins import super, bytes
from future.moves.itertools import zip_longest
from uuid import uuid4

import olm

from ..api import Api
from ..exceptions import LocalProtocolError


class SasState(Enum):
    created = 0
    started = 1
    accepted = 2
    key_received = 3
    canceled = 4


class Sas(olm.Sas):
    _sas_method_v1 = "m.sas.v1"
    _key_agreement_v1 = "curve25519"
    _hash_v1 = "sha256"
    _mac_v1 = "hkdf-hmac-sha256"
    _strings_v1 = ["emoji", "decimal"]

    emoji = [
        ("🐶", "Dog"), ("🐱", "Cat"), ("🦁", "Lion"),
        ("🐎", "Horse"), ("🦄", "Unicorn"), ("🐷", "Pig"),
        ("🐘", "Elephant"), ("🐰", "Rabbit"), ("🐼", "Panda"),
        ("🐓", "Rooster"), ("🐧", "Penguin"), ("🐢", "Turtle"),
        ("🐟", "Fish"), ("🐙", "Octopus"), ("🦋", "Butterfly"),
        ("🌷", "Flower"), ("🌳", "Tree"), ("🌵", "Cactus"),
        ("🍄", "Mushroom"), ("🌏", "Globe"), ("🌙", "Moon"),
        ("☁️ ", "Cloud"), ("🔥", "Fire"), ("🍌", "Banana"),
        ("🍎", "Apple"), ("🍓", "Strawberry"), ("🌽", "Corn"),
        ("🍕", "Pizza"), ("🎂", "Cake"), ("❤️ ", "Heart"),
        ("😀", "Smiley"), ("🤖", "Robot"), ("🎩", "Hat"),
        ("👓", "Glasses"), ("🔧", "Wrench"), ("🎅", "Santa"),
        ("👍", "Thumbs up"), ("☂️ ", "Umbrella"), ("⌛", "Hourglass"),
        ("⏰", "Clock"), ("🎁", "Gift"), ("💡", "Light Bulb"),
        ("📕", "Book"), ("✏️ ", "Pencil"), ("📎", "Paperclip"),
        ("✂️ ", "Scissors"), ("🔒", "Lock"), ("🔑", "Key"),
        ("🔨", "Hammer"), ("☎️ ", "Telephone"), ("🏁", "Flag"),
        ("🚂", "Train"), ("🚲", "Bicycle"), ("✈️ ", "Airplane"),
        ("🚀", "Rocket"), ("🏆", "Trophy"), ("⚽", "Ball"),
        ("🎸", "Guitar"), ("🎺", "Trumpet"), ("🔔", "Bell"),
        ("⚓", "Anchor"), ("🎧", "Headphones"), ("📁", "Folder"),
        ("📌", "Pin")
    ]

    def __init__(
        self,
        own_user,
        own_device,
        own_fp_key,
        other_user,
        other_device,
        transaction_id=None,
        short_auth_string=None
    ):
        self.own_user = own_user
        self.own_device = own_device
        self.own_fp_key = own_fp_key

        self.transaction_id = transaction_id or str(uuid4())
        self.other_user = other_user

        self.other_device = other_device
        self.short_auth_string = short_auth_string or ["emoji", "decimal"]
        self.state = SasState.created
        self.we_started_it = True
        self.commitment = None
        self.cancel_reason = None
        super().__init__()

    @classmethod
    def from_key_verification_start(
        cls,
        own_user,
        own_device,
        own_fp_key,
        event
    ):
        """Create a SAS object from a KeyVerificationStart event."""
        obj = cls(
            own_user,
            own_device,
            own_fp_key,
            event.sender,
            event.from_device,
            event.transaction_id,
            event.short_authentication_string
        )
        obj.we_started_it = False
        obj.state = SasState.started

        string_content = Api.to_canonical_json(event.source["content"])
        obj.commitment = olm.sha256(obj.pubkey + string_content)

        if (Sas._sas_method_v1 not in event.method
                or Sas._key_agreement_v1 not in event.key_agreement_protocols
                or Sas._hash_v1 not in event.hashes
                or Sas._mac_v1 not in event.message_authentication_codes
                or ("emoji" not in event.short_authentication_string
                    and "decimal" not in event.short_authentication_string)):
            obj.state = SasState.canceled

        return obj

    def receive_key(self, event):
        if self.other_key_set:
            raise LocalProtocolError("Other key already set")
        # TODO abort if the sender or transaciton id don't match
        self.set_their_pubkey(event.key)

    def _grouper(self, iterable, n, fillvalue=None):
        """Collect data into fixed-length chunks or blocks."""
        # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
        args = [iter(iterable)] * n
        return zip_longest(*args, fillvalue=fillvalue)

    def get_emoji(self):
        if self.we_started_it:
            info = ("MATRIX_KEY_VERIFICATION_SAS"
                    "{user_id}{device_id}{user_id}{transaction_id}".format(
                        user_id=self.other_user, device_id=self.other_device,
                        transaction_id=self.transaction_id))
        else:
            info = ("MATRIX_KEY_VERIFICATION_SAS"
                    "{first_user}{first_device}"
                    "{second_user}{second_device}{transaction_id}".format(
                        first_user=self.other_user,
                        first_device=self.other_device,
                        second_user=self.own_user,
                        second_device=self.own_device,
                        transaction_id=self.transaction_id))

        return self.generate_emoji(info)

    def generate_emoji(self, extra_info):
        """Create a list of emojies from our shared secret."""
        generated_bytes = self.generate_bytes(extra_info, 6)
        number = "".join([format(x, "08b") for x in bytes(generated_bytes)])
        return [
            self.emoji[int(x, 2)] for x in
            map("".join, list(self._grouper(number[:42], 6)))
        ]

    def start_verification(self):
        """Create a content dictionary to start the verification."""
        if not self.we_started_it:
            raise LocalProtocolError("Verification was not started by us, "
                                     "can't send start verification message.")

        if self.state == SasState.canceled:
            raise LocalProtocolError("SAS verification was canceled, "
                                     "can't send start verification message.")

        content = {
            "from_device": self.own_device,
            "method": self._sas_method_v1,
            "transaction_id": self.transaction_id,
            "key_agreement_protocols": ["curve25519"],
            "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256"],
            "short_authentication_string": ["decimal", "emoji"],
        }

        return content

    def accept_verification(self):
        """Create a content dictionary to accept the verification offer."""
        if self.we_started_it:
            raise LocalProtocolError("Verification was started by us, can't "
                                     "accept offer.")

        if self.state == SasState.canceled:
            raise LocalProtocolError("SAS verification was canceled , can't "
                                     "accept offer.")

        sas_strings = []

        if "emoji" in self.short_auth_string:
            sas_strings.append("emoji")

        if "decimal" in self.short_auth_string:
            sas_strings.append("decimal")

        content = {
            "transaction_id": self.transaction_id,
            "key_agreement_protocol": self._key_agreement_v1,
            "hash": self._hash_v1,
            "message_authentication_code": self._mac_v1,
            "short_authentication_string": sas_strings,
            "commitment": self.commitment,
        }

        return content

    def share_key(self):
        """Create a dictionary containing our public key."""
        return {
            "transaction_id": self.transaction_id,
            "key": self.pubkey
        }

    def get_mac(self):
        """Create a dictionary containing our MAC."""
        key_id = "ed25519:{}".format(self.own_device)

        info = ("MATRIX_KEY_VERIFICATION_MAC"
                "{first_user}{first_device}"
                "{second_user}{second_device}{transaction_id}".format(
                    first_user=self.own_user,
                    first_device=self.own_device,
                    second_user=self.other_user,
                    second_device=self.other_device,
                    transaction_id=self.transaction_id))

        mac = {
            key_id: self.calculate_mac(self.own_fp_key, info + key_id)
        }

        return {
            "mac": mac,
            "keys": self.calculate_mac(key_id, info + "KEY_IDS"),
            "transaction_id": self.transaction_id,
        }
