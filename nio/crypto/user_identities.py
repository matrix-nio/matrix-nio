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


from typing import Any, Dict, List
from dataclasses import dataclass, field
from enum import Enum
from olm import ed25519_verify
from olm.utility import OlmVerifyError
from .device import OlmDevice
from ..api import Api


class CrossSigningKeyType(Enum):
    Master = 0
    SelfSign = 1
    UserSign = 2


class IdentityChange(Enum):
    NoChange = 0
    Master = 1
    SubKey = 2


@dataclass
class CrossSigningPubkey:
    user_id: str = field()
    keys: Dict[str, str] = field()
    signatures: Dict[str, Dict[str, str]] = field()
    usage: List[str] = field()

    def as_signature_message(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "keys": self.keys,
            "usage": self.usage,
        }


def verify_message(
    key_id: str, key: str, message: Dict[Any, Any], signature: str
):
    # We don't know yet how to verify signatures that aren't signed by
    # an ed25519 key.
    if not key_id.startswith("ed25519"):
        return False

    try:
        ed25519_verify(key, Api.to_canonical_json(message), signature)
        return True
    except OlmVerifyError:
        return False


def get_signatures(
    keys: Dict[str, str], signatures: Dict[str, str]
) -> Dict[str, str]:
    return {
        key_id: signatures[key_id] for key_id in keys if key_id in signatures
    }


def verify_cross_signing_key(
    signer: CrossSigningPubkey, signee: CrossSigningPubkey
) -> bool:
    user_signatures = signee.signatures.get(signer.user_id)

    if not user_signatures:
        return False

    signatures = get_signatures(signer.keys, user_signatures)
    message = signee.as_signature_message()
    verified = False

    for key_id, signature in signatures.items():
        key = signer.keys[key_id]

        if verify_message(key_id, key, message, signature):
            verified = True
        else:
            return False

    return verified


class MasterPubkeys(CrossSigningPubkey):
    def verify_cross_signing_subkey(self, key: CrossSigningPubkey) -> bool:
        return verify_cross_signing_key(self, key)


class SelfSigningPubkeys(CrossSigningPubkey):
    def verify_device_signature(self, device: OlmDevice):
        verified = False

        user_signatures = device.signatures.get(self.user_id, {})

        signatures = get_signatures(self.keys, user_signatures)
        message = device.as_signature_message()

        for key_id, signature in signatures.items():
            key = self.keys[key_id]

            if verify_message(key_id, key, message, signature):
                verified = True
            else:
                return False

        return verified


class UserSigningPubkeys(CrossSigningPubkey):
    def verify_cross_signing_master_key(self, key: MasterPubkeys) -> bool:
        return verify_cross_signing_key(self, key)


@dataclass
class UserIdentity:
    user_id: str = field()
    master_keys: MasterPubkeys = field()
    user_signing_keys: UserSigningPubkeys = field()
    self_signing_keys: SelfSigningPubkeys = field()

    def update(
        self,
        master: MasterPubkeys,
        user: UserSigningPubkeys,
        self_signing: SelfSigningPubkeys,
    ) -> IdentityChange:
        if (
            self.master_keys == master
            and self.user_signing_keys == user
            and self.self_signing_keys == self_signing
        ):
            return IdentityChange.NoChange

        self.master_keys = master
        self.user_signing_keys = user
        self.self_signing_keys = self_signing

        if self.master_keys != master:
            return IdentityChange.Master

        return IdentityChange.SubKey

    def is_device_signed(self, device: OlmDevice):
        # A user is supposed to only sign it's own devices directly with the
        # self signing key. Don't bother checking if the user ids don't match.
        if device.user_id != self.user_id:
            return False

        signing_key = self.self_signing_keys

        return signing_key.verify_device_signature(device)
