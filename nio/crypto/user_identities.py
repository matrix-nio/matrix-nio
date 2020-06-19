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


class CrossSigningKeyType(Enum):
    Master = 0
    SelfSign = 1
    UserSign = 2


@dataclass
class CrossSigningPubkey:
    key_id: str = field()
    keys: Dict[str, str] = field()
    signatures: Dict[str, Dict[str, str]] = field()
    usage: List[str] = field()


class MasterPubkeys(CrossSigningPubkey):
    @property
    def ed25519(self) -> str:
        return self.keys[f"ed25519:{self.key_id}"]


class SelfSigningPubkeys(CrossSigningPubkey):
    pass


class UserSigningPubkeys(CrossSigningPubkey):
    pass


@dataclass
class UserIdentity:
    user_id: str = field()
    main_key_id: str = field()
    master_keys: MasterPubkeys = field()
    user_signing_keys: UserSigningPubkeys = field()
    self_signing_keys: SelfSigningPubkeys = field()
