# -*- coding: utf-8 -*-

# Copyright 2018 Zil0
# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This function is part of the matrix-python-sdk and is distributed
# under the APACHE 2.0 licence.

"""Matrix encryption algorithms for file uploads."""

import base64

import unpaddedbase64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter

from ..exceptions import EncryptionError


def decrypt_attachment(ciphertext, key, hash, iv):
    """Decrypt an encrypted attachment.

    Args:
        ciphertext (bytes): The data to decrypt.
        key (str): AES_CTR JWK key object.
        hash (str): Base64 encoded SHA-256 hash of the ciphertext.
        iv (str): Base64 encoded 16 byte AES-CTR IV.
    Returns:
        The plaintext bytes.
    Raises:
        EncryptionError if the integrity check fails.


    """
    expected_hash = unpaddedbase64.decode_base64(hash)

    h = SHA256.new()
    h.update(ciphertext)

    if h.digest() != expected_hash:
        raise EncryptionError("Mismatched SHA-256 digest.")

    try:
        key = unpaddedbase64.decode_base64(key)
    except (base64.binascii.Error, TypeError):
        raise EncryptionError("Error decoding key.")

    try:
        # Drop last 8 bytes, which are 0
        iv = unpaddedbase64.decode_base64(iv)[:8]
    except (base64.binascii.Error, TypeError):
        raise EncryptionError("Error decoding initial values.")

    ctr = Counter.new(64, prefix=iv, initial_value=0)

    try:
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    except ValueError as e:
        raise EncryptionError(e)

    return cipher.decrypt(ciphertext)


def encrypt_attachment(plaintext):
    """Encrypt a plaintext in order to send it as an encrypted attachment.

    Args:
        plaintext (bytes): The data to encrypt.
    Returns:
        A tuple of the ciphertext bytes and a dict containing the info needed
        to decrypt data. The keys are:
        | key: AES-CTR JWK key object.
        | iv: Base64 encoded 16 byte AES-CTR IV.
        | hashes.sha256: Base64 encoded SHA-256 hash of the ciphertext.

    """
    # 8 bytes IV
    iv = Random.new().read(8)
    # 8 bytes counter, prefixed by the IV
    ctr = Counter.new(64, prefix=iv, initial_value=0)

    key = Random.new().read(32)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    ciphertext = cipher.encrypt(plaintext)

    h = SHA256.new()
    h.update(ciphertext)
    digest = h.digest()

    json_web_key = {
        "kty": "oct",
        "alg": "A256CTR",
        "ext": True,
        "k": unpaddedbase64.encode_base64(key, urlsafe=True),
        "key_ops": ["encrypt", "decrypt"]
    }
    keys = {
        "v": "v2",
        "key": json_web_key,
        # Send IV concatenated with counter
        "iv": unpaddedbase64.encode_base64(iv + b"\x00" * 8),
        "hashes": {
            "sha256": unpaddedbase64.encode_base64(digest),
        }
    }
    return ciphertext, keys
