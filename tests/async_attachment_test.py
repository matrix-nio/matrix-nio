from pathlib import Path

import aiofiles
import pytest
import unpaddedbase64
from Crypto import Random  # nosec

from nio import EncryptionError
from nio.crypto import async_decrypt_attachment, async_encrypt_attachment

FILEPATH = "tests/data/test_bytes"


@pytest.mark.asyncio()
class TestClass:
    async def _get_data_cypher_keys(self, data=b"Test bytes"):
        *chunks, keys = [i async for i in async_encrypt_attachment(data)]
        return (data, b"".join(chunks), keys)

    async def _generate(self, ciphertext):
        for i in range(0, len(ciphertext), 4):
            yield ciphertext[i : i + 4]

    async def test_encrypt(self, data=b"Test bytes", large=False):
        _, ciphertext, keys = await self._get_data_cypher_keys(data)

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            keys["iv"],
        )
        plaintext = b"".join([i async for i in plaintext_generator])

        assert plaintext == b"Test bytes" * (16384 if large else 1)

    async def test_encrypt_large_bytes(self):
        # Makes sure our bytes chunking in async_generator_from_data
        # is working correctly
        await self.test_encrypt(b"Test bytes" * 16384, large=True)

    async def test_encrypt_str(self):
        await self.test_encrypt(FILEPATH)

    async def test_encrypt_path_object(self):
        await self.test_encrypt(Path(FILEPATH))

    async def test_encrypt_iterable(self):
        await self.test_encrypt([b"Test ", b"bytes"])

    async def test_encrypt_async_iterable(self):
        async def async_gen():
            yield b"Test "
            yield b"bytes"

        await self.test_encrypt(async_gen())

    async def test_encrypt_file_object(self):
        await self.test_encrypt(open(FILEPATH, "rb"))  # noqa: ASYNC101

    async def test_encrypt_async_file_object(self):
        await self.test_encrypt(await aiofiles.open(FILEPATH, "rb"))

    async def test_encrypt_bad_argument_type(self):
        with pytest.raises(TypeError):
            await self.test_encrypt(123)

    async def test_hash_verification(self):
        _data, ciphertext, keys = await self._get_data_cypher_keys()

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            keys["key"]["k"],
            "Fake hash",
            keys["iv"],
        )
        with pytest.raises(EncryptionError):
            [i async for i in plaintext_generator]

    async def test_invalid_key(self):
        _data, ciphertext, keys = await self._get_data_cypher_keys()

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            "Fake key",
            keys["hashes"]["sha256"],
            keys["iv"],
        )
        with pytest.raises(EncryptionError):
            [i async for i in plaintext_generator]

    async def test_invalid_iv(self):
        _data, ciphertext, keys = await self._get_data_cypher_keys()

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            "Fake iv",
        )
        with pytest.raises(EncryptionError):
            [i async for i in plaintext_generator]

    async def test_short_key(self):
        _data, ciphertext, keys = await self._get_data_cypher_keys()

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            unpaddedbase64.encode_base64(b"Fake key", urlsafe=True),
            keys["hashes"]["sha256"],
            keys["iv"],
        )
        with pytest.raises(EncryptionError):
            [i async for i in plaintext_generator]

    async def test_short_iv(self):
        data, ciphertext, keys = await self._get_data_cypher_keys()

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            unpaddedbase64.encode_base64(b"F" + b"\x00" * 8),
        )
        plaintext = b"".join([i async for i in plaintext_generator])
        assert plaintext != data

    async def test_fake_key(self):
        data, ciphertext, keys = await self._get_data_cypher_keys()

        fake_key = Random.new().read(32)

        plaintext_generator = async_decrypt_attachment(
            self._generate(ciphertext),
            unpaddedbase64.encode_base64(fake_key, urlsafe=True),
            keys["hashes"]["sha256"],
            keys["iv"],
        )
        plaintext = b"".join([i async for i in plaintext_generator])
        assert plaintext != data
