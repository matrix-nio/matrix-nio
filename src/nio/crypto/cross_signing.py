# Copyright © 2026 Christian González <christian.gonzalez@nerdocs.at>
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

"""Cross-signing key model and signing helpers.

The `cross-signing`_ module of the Matrix spec lets a user sign their own
devices with a self-signing key and other users' master keys with a
user-signing key, both of which are signed by the user's master key. This
module holds the public key objects as returned by the ``/keys/query``
endpoint, the private key seeds of our own user and the JSON signing and
verification helpers used for them.

.. _cross-signing: https://spec.matrix.org/v1.19/client-server-api/#cross-signing
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import vodozemac
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from unpaddedbase64 import encode_base64

from ..api import Api

MASTER_KEY_USAGE = "master"
SELF_SIGNING_KEY_USAGE = "self_signing"
USER_SIGNING_KEY_USAGE = "user_signing"


def _signing_key(seed: bytes) -> ECC.EccKey:
    return ECC.construct(curve="Ed25519", seed=seed)  # type: ignore[arg-type]


def public_key_from_seed(seed: bytes) -> str:
    """Derive the unpadded base64 encoded ed25519 public key from a seed.

    Args:
        seed (bytes): The 32 byte private key seed.
    """
    raw = _signing_key(seed).public_key().export_key(format="raw")
    return encode_base64(raw)


def sign_json(seed: bytes, json_dict: dict[str, Any]) -> str:
    """Sign a JSON object with an ed25519 key.

    The ``signatures`` and ``unsigned`` properties are left out and the
    remaining object is signed in its canonical JSON form, as described in
    the "Signing JSON" appendix of the spec.

    Args:
        seed (bytes): The 32 byte seed of the ed25519 signing key.
        json_dict (Dict): The JSON object that should be signed.

    Returns the unpadded base64 encoded signature.
    """
    unsigned = {
        key: value
        for key, value in json_dict.items()
        if key not in ("signatures", "unsigned")
    }
    message = Api.to_canonical_json(unsigned).encode()
    signer = eddsa.new(_signing_key(seed), "rfc8032")
    return encode_base64(signer.sign(message))


def verify_signed_json(
    json_dict: dict[str, Any], user_id: str, key_id: str, public_key: str
) -> bool:
    """Verify the signature of a JSON object.

    Args:
        json_dict (Dict): The JSON object holding a ``signatures`` property
            of the form ``{user_id: {key_id: signature}}``.
        user_id (str): The user id under which the signature is stored.
        key_id (str): The key id of the signature, e.g. ``ed25519:DEVICEID``
            for a device key or ``ed25519:<public key>`` for a cross-signing
            key.
        public_key (str): The base64 encoded ed25519 public key that was
            used to sign the object.

    Returns True if the signature is valid, False if it is missing or
    invalid.
    """
    try:
        signature_base64 = json_dict["signatures"][user_id][key_id]
    except (KeyError, TypeError):
        return False

    unsigned = {
        key: value
        for key, value in json_dict.items()
        if key not in ("signatures", "unsigned")
    }

    try:
        key = vodozemac.Ed25519PublicKey.from_base64(public_key)
        signature = vodozemac.Ed25519Signature.from_base64(signature_base64)
        key.verify_signature(Api.to_canonical_json(unsigned).encode(), signature)
    except (vodozemac.SignatureException, vodozemac.KeyException, TypeError):
        return False

    return True


@dataclass
class CrossSigningKey:
    """A public cross-signing key of a user.

    Attributes:
        user_id (str): The id of the user the key belongs to.
        usage (List[str]): The usage of the key, one of ``master``,
            ``self_signing`` or ``user_signing``.
        public_key (str): The unpadded base64 encoded ed25519 public key.
        signatures (Dict): The signatures of the key object, a map from user
            id to a map from key id to signature.
    """

    user_id: str = field()
    usage: list[str] = field()
    public_key: str = field()
    signatures: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def key_id(self) -> str:
        """The key id, ``ed25519:<public key>``."""
        return f"ed25519:{self.public_key}"

    def as_dict(self) -> dict[str, Any]:
        """Convert the key into the JSON object used by the keys endpoints."""
        key_dict: dict[str, Any] = {
            "user_id": self.user_id,
            "usage": self.usage,
            "keys": {self.key_id: self.public_key},
        }

        if self.signatures:
            key_dict["signatures"] = self.signatures

        return key_dict

    @classmethod
    def from_dict(cls, key_dict: dict[str, Any]) -> CrossSigningKey:
        """Create a CrossSigningKey from a key object of a ``/keys/query`` response.

        Raises:
            ValueError if the object doesn't hold exactly one ed25519 key.
        """
        keys = key_dict["keys"]

        if len(keys) != 1:
            raise ValueError("Cross-signing key must hold exactly one key.")

        key_id, public_key = next(iter(keys.items()))

        if key_id != f"ed25519:{public_key}":
            raise ValueError(f"Invalid cross-signing key id {key_id}.")

        return cls(
            key_dict["user_id"],
            list(key_dict["usage"]),
            public_key,
            key_dict.get("signatures", {}),
        )

    def is_signed_by(self, user_id: str, key_id: str, public_key: str) -> bool:
        """Check if the key carries a valid signature by the given key."""
        return verify_signed_json(self.as_dict(), user_id, key_id, public_key)


@dataclass
class UserIdentity:
    """The cross-signing identity of a user.

    Attributes:
        user_id (str): The id of the user.
        master_key (CrossSigningKey): The master key of the user.
        self_signing_key (CrossSigningKey, optional): The self-signing key,
            signed by the master key. Used to sign the user's own devices.
        user_signing_key (CrossSigningKey, optional): The user-signing key,
            signed by the master key. Used to sign other users' master keys,
            only ever known for our own user.
    """

    user_id: str = field()
    master_key: CrossSigningKey = field()
    self_signing_key: CrossSigningKey | None = None
    user_signing_key: CrossSigningKey | None = None

    @property
    def keys(self) -> list[CrossSigningKey]:
        """The list of known keys of this identity."""
        keys = [self.master_key, self.self_signing_key, self.user_signing_key]
        return [key for key in keys if key is not None]


@dataclass
class CrossSigningPrivateKeys:
    """The private cross-signing key seeds of our own user.

    Attributes:
        master (bytes, optional): The 32 byte seed of the master key.
        self_signing (bytes, optional): The 32 byte seed of the self-signing
            key.
        user_signing (bytes, optional): The 32 byte seed of the user-signing
            key.
    """

    master: bytes | None = field(default=None, repr=False)
    self_signing: bytes | None = field(default=None, repr=False)
    user_signing: bytes | None = field(default=None, repr=False)

    @classmethod
    def generate(cls) -> CrossSigningPrivateKeys:
        """Generate a fresh set of cross-signing keys."""
        return cls(os.urandom(32), os.urandom(32), os.urandom(32))

    def __bool__(self) -> bool:
        return any((self.master, self.self_signing, self.user_signing))

    def seed(self, usage: str) -> bytes | None:
        """Get the seed of the key with the given usage."""
        return getattr(self, usage)

    def public_key(self, usage: str) -> str | None:
        """Get the base64 encoded public key of the key with the given usage."""
        seed = self.seed(usage)
        return public_key_from_seed(seed) if seed else None

    def sign(self, usage: str, json_dict: dict[str, Any]) -> str:
        """Sign a JSON object with the key of the given usage.

        Raises:
            ValueError if the key is not known.
        """
        seed = self.seed(usage)

        if not seed:
            raise ValueError(f"The {usage} key is not known.")

        return sign_json(seed, json_dict)

    def as_identity(self, user_id: str) -> UserIdentity:
        """Create the public identity that should be uploaded for these keys.

        The self-signing and user-signing keys are signed by the master key.

        Raises:
            ValueError if the master key is not known.
        """
        master_seed = self.master

        if not master_seed:
            raise ValueError("The master key is not known.")

        master = CrossSigningKey(
            user_id, [MASTER_KEY_USAGE], public_key_from_seed(master_seed)
        )

        def subkey(usage: str) -> CrossSigningKey | None:
            seed = self.seed(usage)

            if not seed:
                return None

            key = CrossSigningKey(user_id, [usage], public_key_from_seed(seed))
            key.signatures = {
                user_id: {master.key_id: sign_json(master_seed, key.as_dict())}
            }
            return key

        return UserIdentity(
            user_id,
            master,
            subkey(SELF_SIGNING_KEY_USAGE),
            subkey(USER_SIGNING_KEY_USAGE),
        )
