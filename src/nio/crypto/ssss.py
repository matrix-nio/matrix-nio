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

"""Secret Storage (SSSS) primitives.

This module implements the client-side cryptography of the Matrix `Secret
Storage`_ module: the recovery key encoding, the passphrase key derivation
and the ``m.secret_storage.v1.aes-hmac-sha2`` secret encryption. All
functions are pure and perform no I/O; fetching and storing the account data
events is left to the client.

Malformed or wrong input (bad recovery key, wrong secret storage key, failed
MAC check) raises ``ValueError``.

.. _Secret Storage: https://spec.matrix.org/v1.19/client-server-api/#secret-storage
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Util import Counter
from unpaddedbase64 import decode_base64, encode_base64

SECRET_STORAGE_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
PASSPHRASE_ALGORITHM = "m.pbkdf2"

RECOVERY_KEY_PREFIX = b"\x8b\x01"
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded

    # Leading zero bytes are encoded as leading '1' characters.
    padding = len(data) - len(data.lstrip(b"\x00"))
    return _BASE58_ALPHABET[0] * padding + encoded


def _base58_decode(data: str) -> bytes:
    number = 0

    for char in data:
        index = _BASE58_ALPHABET.find(char)
        if index == -1:
            raise ValueError(f"Invalid character in recovery key: {char!r}")
        number = number * 58 + index

    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    padding = len(data) - len(data.lstrip(_BASE58_ALPHABET[0]))
    return b"\x00" * padding + decoded


def encode_recovery_key(key: bytes) -> str:
    """Encode a 32 byte secret storage key as a user facing recovery key.

    The key is prefixed with the bytes ``0x8B 0x01``, followed by a parity
    byte (XOR of all preceding bytes), base58 encoded and split into groups
    of four characters.

    Args:
        key (bytes): The 32 byte secret storage key.

    Raises:
        ValueError if the key has the wrong length.
    """
    if len(key) != 32:
        raise ValueError("Secret storage key must be 32 bytes long.")

    data = RECOVERY_KEY_PREFIX + key
    parity = 0
    for byte in data:
        parity ^= byte

    encoded = _base58_encode(data + bytes([parity]))
    return " ".join(encoded[i : i + 4] for i in range(0, len(encoded), 4))


def decode_recovery_key(recovery_key: str) -> bytes:
    """Decode a user entered recovery key into the 32 byte secret storage key.

    Whitespace is ignored, so the key can be entered with or without the
    grouping spaces.

    Args:
        recovery_key (str): The base58 encoded recovery key.

    Raises:
        ValueError if the recovery key is malformed, has the wrong prefix or
            fails the parity check.
    """
    decoded = _base58_decode("".join(recovery_key.split()))

    if len(decoded) != 35 or not decoded.startswith(RECOVERY_KEY_PREFIX):
        raise ValueError("Invalid recovery key: wrong length or prefix.")

    parity = 0
    for byte in decoded:
        parity ^= byte

    if parity != 0:
        raise ValueError("Invalid recovery key: parity check failed.")

    return decoded[2:-1]


def key_from_passphrase(
    passphrase: str, salt: str, iterations: int, bits: int = 256
) -> bytes:
    """Derive a secret storage key from a passphrase.

    Implements the ``m.pbkdf2`` algorithm of the secret storage key
    description: PBKDF2 with HMAC-SHA-512.

    Args:
        passphrase (str): The user's passphrase.
        salt (str): The salt from the ``passphrase`` property of the key
            description.
        iterations (int): The number of PBKDF2 rounds.
        bits (int, optional): The number of bits to generate, defaults to
            256.
    """
    # Pass bytes, pycryptodome would encode a str as latin-1.
    return PBKDF2(
        passphrase.encode(),  # type: ignore[arg-type]
        salt.encode(),
        bits // 8,
        iterations,
        hmac_hash_module=SHA512,
    )


def _derive_keys(key: bytes, name: str) -> tuple[bytes, bytes]:
    """Derive the AES and MAC keys for a secret from the secret storage key.

    HKDF-SHA-256 with a salt of 32 zero bytes and the secret name as the
    info parameter, the first 32 bytes are the AES key and the next 32 bytes
    the MAC key.
    """
    derived = HKDF(key, 64, b"\x00" * 32, SHA256, context=name.encode())
    assert isinstance(derived, bytes)
    return derived[:32], derived[32:]


def _aes_ctr(aes_key: bytes, iv: bytes, data: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(data)


def _mac(mac_key: bytes, ciphertext: bytes) -> bytes:
    return HMAC.new(mac_key, ciphertext, SHA256).digest()


def encrypt_secret(key: bytes, name: str, plaintext: bytes) -> dict[str, str]:
    """Encrypt a secret with the ``m.secret_storage.v1.aes-hmac-sha2`` algorithm.

    Args:
        key (bytes): The 32 byte secret storage key.
        name (str): The name of the secret, e.g. ``m.cross_signing.master``.
            This is the event type under which the secret is stored.
        plaintext (bytes): The data to encrypt.

    Returns a dictionary with the unpadded base64 encoded ``iv``,
    ``ciphertext`` and ``mac`` properties, ready to be stored under the key
    id in the ``encrypted`` property of the secret's account data event.
    """
    aes_key, mac_key = _derive_keys(key, name)

    # 128 bits IV with bit 63 set to 0, as specified.
    iv = int.from_bytes(Random.new().read(16), "big")
    iv &= ~(1 << 63)
    iv_bytes = iv.to_bytes(16, "big")

    ciphertext = _aes_ctr(aes_key, iv_bytes, plaintext)

    return {
        "iv": encode_base64(iv_bytes),
        "ciphertext": encode_base64(ciphertext),
        "mac": encode_base64(_mac(mac_key, ciphertext)),
    }


def decrypt_secret(key: bytes, name: str, encrypted: dict[str, str]) -> bytes:
    """Decrypt a secret encrypted with ``m.secret_storage.v1.aes-hmac-sha2``.

    Args:
        key (bytes): The 32 byte secret storage key.
        name (str): The name of the secret, e.g. ``m.cross_signing.master``.
        encrypted (Dict[str, str]): The dictionary holding the base64 encoded
            ``iv``, ``ciphertext`` and ``mac`` properties.

    Raises:
        ValueError if the encrypted dictionary is malformed or the MAC check
            fails, which usually means that the wrong secret storage key was
            used.
    """
    aes_key, mac_key = _derive_keys(key, name)

    try:
        iv = decode_base64(encrypted["iv"])
        ciphertext = decode_base64(encrypted["ciphertext"])
        mac = decode_base64(encrypted["mac"])
    except (KeyError, TypeError, AttributeError) as e:
        raise ValueError(f"Malformed encrypted secret {name}: {e}") from e

    if not hmac.compare_digest(_mac(mac_key, ciphertext), mac):
        raise ValueError(f"MAC check failed for secret {name}.")

    return _aes_ctr(aes_key, iv, ciphertext)


def check_key(key: bytes, iv: str | None, mac: str | None) -> bool:
    """Check a secret storage key against the ``iv`` and ``mac`` of its key description.

    The check encrypts 32 zero bytes with the empty string as the secret name
    and compares the resulting MAC. If the key description carries no ``iv``
    or ``mac`` the key can't be checked and is assumed to be valid, as
    required by the spec.

    Args:
        key (bytes): The 32 byte secret storage key.
        iv (str, optional): The base64 encoded ``iv`` of the key description.
        mac (str, optional): The base64 encoded ``mac`` of the key description.
    """
    if iv is None or mac is None:
        return True

    aes_key, mac_key = _derive_keys(key, "")
    ciphertext = _aes_ctr(aes_key, decode_base64(iv), b"\x00" * 32)

    return hmac.compare_digest(_mac(mac_key, ciphertext), decode_base64(mac))


@dataclass
class SecretStorageKeyInfo:
    """The description of a secret storage key.

    This is the content of a ``m.secret_storage.key.<key id>`` account data
    event.

    Attributes:
        key_id (str): The id of the key.
        algorithm (str): The encryption algorithm, currently only
            ``m.secret_storage.v1.aes-hmac-sha2`` is defined.
        name (str, optional): A human readable name of the key.
        passphrase (Dict, optional): If present, the key can be derived from
            a passphrase with the parameters in this dictionary.
        iv (str, optional): The base64 encoded IV used to check the key.
        mac (str, optional): The base64 encoded MAC used to check the key.
    """

    key_id: str = field()
    algorithm: str = field()
    name: str | None = None
    passphrase: dict[str, Any] | None = None
    iv: str | None = None
    mac: str | None = None

    @classmethod
    def from_dict(cls, key_id: str, content: dict[str, Any]) -> SecretStorageKeyInfo:
        """Create a SecretStorageKeyInfo from the event content.

        Args:
            key_id (str): The id of the key.
            content (Dict): The content of the ``m.secret_storage.key.<key
                id>`` account data event.

        Raises:
            ValueError if the algorithm is not supported.
        """
        algorithm = content.get("algorithm")

        if algorithm != SECRET_STORAGE_ALGORITHM:
            raise ValueError(f"Unsupported secret storage algorithm {algorithm}.")

        return cls(
            key_id,
            algorithm,
            content.get("name"),
            content.get("passphrase"),
            content.get("iv"),
            content.get("mac"),
        )

    def key_from_passphrase(self, passphrase: str) -> bytes:
        """Derive the secret storage key from a passphrase.

        Args:
            passphrase (str): The user's passphrase.

        Raises:
            ValueError if the key description carries no passphrase
                parameters or uses an unsupported passphrase algorithm.
        """
        if not self.passphrase:
            raise ValueError("Secret storage key can't be derived from a passphrase.")

        algorithm = self.passphrase.get("algorithm")

        if algorithm != PASSPHRASE_ALGORITHM:
            raise ValueError(f"Unsupported passphrase algorithm {algorithm}.")

        return key_from_passphrase(
            passphrase,
            self.passphrase["salt"],
            self.passphrase["iterations"],
            self.passphrase.get("bits", 256),
        )

    def check_key(self, key: bytes) -> bool:
        """Check if the given secret storage key matches this key description."""
        return check_key(key, self.iv, self.mac)
