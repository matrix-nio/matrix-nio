import pytest

from os import path

from hypothesis import given
from hypothesis.strategies import binary

from nio.crypto.key_export import (
    encrypt,
    decrypt,
    decrypt_and_read,
    encrypt_and_save
)

class TestClass(object):
    @given(binary())
    def test_encrypt(self, data):
        passphrase = "A secret"
        cyphertext = encrypt(data, passphrase, count=10)
        plaintext = decrypt(cyphertext, passphrase)

        assert data == plaintext

    def test_encrypt_rounds(self, benchmark):
        data = b"data"
        passphrase = "A secret"
        benchmark(encrypt, data, passphrase, count=10000)

    def test_decrypt_failure(self):
        data = b"data"
        passphrase = "A secret"
        cyphertext = encrypt(data, passphrase, count=10)

        with pytest.raises(ValueError):
            plaintext = decrypt(cyphertext, "Fake key")

    def test_encrypt_file(self, tempdir):
        data = b"data"
        passphrase = "A secret"
        file = path.join(tempdir, "keys_file")

        encrypt_and_save(data, file, passphrase, count=10)

        plaintext = decrypt_and_read(file, passphrase)
        assert plaintext == data
