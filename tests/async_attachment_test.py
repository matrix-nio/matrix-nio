import sys
from pathlib import Path

import aiofiles
import pytest
import unpaddedbase64
from Crypto import Random  # nosec

from nio import EncryptionError
from nio.crypto import async_encrypt_attachment, decrypt_attachment


FILEPATH = "tests/data/test_bytes"

@pytest.mark.skipif(
    sys.version_info < (3, 5), reason="Python 3 specific asyncio tests",
)
class TestClass:
    async def _get_data_cypher_keys(self, data=b"Test bytes"):
        *chunks, keys = [i async for i in async_encrypt_attachment(data)]
        return (data, b"".join(chunks), keys)


    async def test_encrypt(self, data=b"Test bytes", large=False):
        _, cyphertext, keys = await self._get_data_cypher_keys(data)

        plaintext = decrypt_attachment(
            cyphertext,
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            keys["iv"],
        )

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
        await self.test_encrypt(open(FILEPATH, "rb"))

    async def test_encrypt_async_file_object(self):
        await self.test_encrypt(await aiofiles.open(FILEPATH, "rb"))

    async def test_encrypt_bad_argument_type(self):
        with pytest.raises(TypeError):
            await self.test_encrypt(123)

    async def test_hash_verification(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                keys["key"]["k"],
                "Fake hash",
                keys["iv"],
            )

    async def test_invalid_key(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                "Fake key",
                keys["hashes"]["sha256"],
                keys["iv"],
            )

    async def test_invalid_iv(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                keys["key"]["k"],
                keys["hashes"]["sha256"],
                "Fake iv",
            )

    async def test_short_key(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        with pytest.raises(EncryptionError):
            decrypt_attachment(
                cyphertext,
                unpaddedbase64.encode_base64(b"Fake key", urlsafe=True),
                keys["hashes"]["sha256"],
                keys["iv"],
            )

    async def test_short_iv(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        plaintext = decrypt_attachment(
            cyphertext,
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            unpaddedbase64.encode_base64(b"F" + b"\x00" * 8),
        )
        assert plaintext != data

    async def test_fake_key(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        fake_key = Random.new().read(32)

        plaintext = decrypt_attachment(
            cyphertext,
            unpaddedbase64.encode_base64(fake_key, urlsafe=True),
            keys["hashes"]["sha256"],
            keys["iv"],
        )
        assert plaintext != data
