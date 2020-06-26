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


from typing import Dict, List
from dataclasses import dataclass, field
from enum import Enum
from olm import ed25519_verify
from olm.utility import OlmVerifyError
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

    def verify_signature(self, cross_signing_key: "CrossSigningPubkey") -> bool:
        signatures = self.find_signatures(cross_signing_key)

        verified = False

        for key_id, signature in signatures.items():
            # We don't know yet how to verify signatures that aren't signed by
            # an ed25519 key.
            if not key_id.startswith("ed25519"):
                continue

            key = self.keys[key_id]

            message = {
                "user_id": cross_signing_key.user_id,
                "keys": cross_signing_key.keys,
                "usage": cross_signing_key.usage,
            }

            try:
                ed25519_verify(key, Api.to_canonical_json(message), signature)
                verified = True
            except OlmVerifyError:
                return False

        return verified


    def find_signatures(self, key: "CrossSigningPubkey") -> Dict[str, str]:
        user_signatures = key.signatures.get(self.user_id)

        if not user_signatures:
            return {}

        return {
            key_id: user_signatures[key_id] for key_id
            in self.keys if key_id in user_signatures
        }


class MasterPubkeys(CrossSigningPubkey):
    pass


class SelfSigningPubkeys(CrossSigningPubkey):
    pass


class UserSigningPubkeys(CrossSigningPubkey):
    pass


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
