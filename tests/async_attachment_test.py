import sys

import pytest
import unpaddedbase64
from Crypto import Random  # nosec

from nio import EncryptionError
from nio.crypto import async_encrypt_attachment, decrypt_attachment


@pytest.mark.skipif(
    sys.version_info < (3, 5), reason="Python 3 specific asyncio tests",
)
class TestClass:
    async def _get_data_cypher_keys(self):
        data          = b"Test bytes"
        *chunks, keys = [i async for i in async_encrypt_attachment(data)]
        return (data, b"".join(chunks), keys)


    async def test_encrypt(self):
        data, cyphertext, keys = await self._get_data_cypher_keys()

        plaintext = decrypt_attachment(
            cyphertext,
            keys["key"]["k"],
            keys["hashes"]["sha256"],
            keys["iv"],
        )

        assert data == plaintext

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
