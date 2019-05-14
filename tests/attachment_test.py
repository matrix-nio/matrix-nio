# -*- coding: utf-8 -*-

import pytest
import unpaddedbase64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

from nio import EncryptionError
from nio.crypto import decrypt_attachment, encrypt_attachment


class TestClass(object):
    def test_encrypt(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        plaintext = decrypt_attachment(
            cyphertext,
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            keys["iv"]
        )

        assert data == plaintext

    def test_hash_verification(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                keys["key"]["k"],
                "Fake hash",
                keys["iv"]
            )

    def test_invalid_key(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                "Fake key",
                keys["hashes"]["sha256"],
                keys["iv"]
            )

    def test_invalid_iv(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                keys["key"]["k"],
                keys["hashes"]["sha256"],
                "Fake iv"
            )

    def test_short_key(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                unpaddedbase64.encode_base64(b"Fake key", urlsafe=True),
                keys["hashes"]["sha256"],
                keys["iv"]
            )

    def test_short_iv(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        plaintext = decrypt_attachment(
            cyphertext,
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            unpaddedbase64.encode_base64(b"F" + b"\x00" * 8),
        )
        assert plaintext != data

    def test_fake_key(self):
        data = b"Test bytes"

        cyphertext, keys = encrypt_attachment(data)

        fake_key = Random.new().read(32)

        plaintext = decrypt_attachment(
            cyphertext,
            unpaddedbase64.encode_base64(fake_key, urlsafe=True),
            keys["hashes"]["sha256"],
            keys["iv"]
        )
        assert plaintext != data
