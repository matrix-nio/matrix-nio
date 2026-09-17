import hashlib
import hmac

import pytest
from hypothesis import given
from hypothesis.strategies import binary
from unpaddedbase64 import decode_base64, encode_base64

from nio.crypto.ssss import (
    SecretStorageKeyInfo,
    _derive_keys,
    check_key,
    decode_recovery_key,
    decrypt_secret,
    encode_recovery_key,
    encrypt_secret,
    key_from_passphrase,
)

KEY = bytes(range(32))
# encodeRecoveryKey(0..31) in matrix-js-sdk starts with "EsSz".
RECOVERY_KEY = "EsSz ykH7 LCZx 7Cae cmKD wcmY JRXi Ybtu 8iQ3 t8Ez nRwK pUY1"
KEY_INFO_IV = "AAECAwQFBgcICQoLDA0ODw"
KEY_INFO_MAC = "ONrOSgDDUXMzIvXsfYBi1m8m075MdjPldfXCxIpU7IY"

# Test vectors from matrix-rust-sdk (crates/matrix-sdk-crypto/src/secret_storage.rs).
RUST_SDK_RECOVERY_KEY = (
    "EsT           pRvZTnjck8    YrhRAtw XLS84Nr2r9S9LGAWDaExVAPBvLRK   "
)
RUST_SDK_DECODED_KEY = bytes.fromhex(
    "9fbd46bb345171c6f6022c9a25d5681ba54eec6a6c4953f3adc0b96e9d91ada3"
)
RUST_SDK_BASE58_KEY_INFO = {
    "recovery_key": "EsTj 3yST y93F SLpB jJsz eAXc 2XzA ygD3 w69H fGaN TKBj jXEd",
    "content": {
        "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
        "iv": "xv5b6/p3ExEw++wTyfSHEg==",
        "mac": "ujBBbXahnTAMkmPUX2/0+VTfUh63pGyVRuBcDMgmJC8=",
    },
}
RUST_SDK_PASSPHRASE_KEY_INFO = {
    "passphrase": "It's a secret to everybody",
    "content": {
        "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
        "iv": "gH2iNpiETFhApvW6/FFEJQ",
        "mac": "9Lw12m5SKDipNghdQXKjgpfdj1/K7HFI2brO+UWAGoM",
        "passphrase": {
            "algorithm": "m.pbkdf2",
            "salt": "IuLnH7S85YtZmkkBJKwNUKxWF42g9O1H",
            "iterations": 10,
        },
    },
}


def reference_hkdf(key, name):
    """Independent stdlib HKDF-SHA256 implementation (zero salt, two blocks)."""
    prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
    info = name.encode()
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + info + b"\x02", hashlib.sha256).digest()
    return t1, t2


class TestRecoveryKey:
    def test_encode(self):
        assert encode_recovery_key(KEY) == RECOVERY_KEY

    def test_decode(self):
        assert decode_recovery_key(RECOVERY_KEY) == KEY
        assert decode_recovery_key(RECOVERY_KEY.replace(" ", "")) == KEY

    def test_rust_sdk_vector(self):
        assert decode_recovery_key(RUST_SDK_RECOVERY_KEY) == RUST_SDK_DECODED_KEY

    @given(binary(min_size=32, max_size=32))
    def test_roundtrip(self, key):
        assert decode_recovery_key(encode_recovery_key(key)) == key

    def test_leading_zero_bytes(self):
        key = bytes(32)
        assert decode_recovery_key(encode_recovery_key(key)) == key

    def test_encode_wrong_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encode_recovery_key(b"short")

    @pytest.mark.parametrize(
        ("recovery_key", "message"),
        [
            ("EsSz ykH7 LCZx 7Cae cmKD wcmY JRXi Ybtu 8iQ3 t8Ez nRwK pUY2", "parity"),
            ("EsTpRvZTnjck8YrhRAtwXLS84Nr2r9S9LGAWDaExVAPBvLRk", "parity"),
            ("AATpRvZTnjck8YrhRAtwXLS84Nr2r9S9LGAWDaExVAPBvLRk", "prefix"),
            ("AATpRvZTnjck8YrhRAtwXLS84Nr2r9S9", "length"),
            (
                "EsSz ykH7 LCZx 7Cae cmKD wcmY JRXi Ybtu 8iQ3 t8Ez nRwK pUY1l",
                "character",
            ),
            ("", "length"),
        ],
    )
    def test_decode_invalid(self, recovery_key, message):
        with pytest.raises(ValueError, match=message):
            decode_recovery_key(recovery_key)


class TestPassphrase:
    def test_matches_stdlib(self):
        expected = hashlib.pbkdf2_hmac("sha512", b"password", b"MmMsAlty", 1000, 32)
        assert key_from_passphrase("password", "MmMsAlty", 1000) == expected

    def test_utf8_passphrase(self):
        expected = hashlib.pbkdf2_hmac(
            "sha512", "pässwörd 🔑".encode(), "sälz".encode(), 10, 32
        )
        assert key_from_passphrase("pässwörd 🔑", "sälz", 10) == expected

    def test_bits(self):
        assert len(key_from_passphrase("password", "salt", 10, bits=512)) == 64


class TestSecrets:
    @pytest.mark.parametrize("name", ["", "m.cross_signing.self_signing"])
    def test_derive_keys_matches_reference(self, name):
        assert _derive_keys(KEY, name) == reference_hkdf(KEY, name)

    def test_check_key(self):
        assert check_key(KEY, KEY_INFO_IV, KEY_INFO_MAC)
        assert not check_key(bytes(32), KEY_INFO_IV, KEY_INFO_MAC)

    def test_check_key_accepts_padded_base64(self):
        assert check_key(KEY, KEY_INFO_IV + "==", KEY_INFO_MAC + "=")

    def test_check_key_without_iv_or_mac(self):
        assert check_key(bytes(32), None, KEY_INFO_MAC)
        assert check_key(bytes(32), KEY_INFO_IV, None)

    def test_check_key_rust_sdk_vector(self):
        key = decode_recovery_key(RUST_SDK_BASE58_KEY_INFO["recovery_key"])
        content = RUST_SDK_BASE58_KEY_INFO["content"]
        assert check_key(key, content["iv"], content["mac"])

    @given(binary())
    def test_encrypt_roundtrip(self, plaintext):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", plaintext)
        assert decrypt_secret(KEY, "m.cross_signing.master", encrypted) == plaintext

    def test_encrypt_output_format(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")
        assert set(encrypted) == {"iv", "ciphertext", "mac"}

        for value in encrypted.values():
            assert "=" not in value

        iv = int.from_bytes(decode_base64(encrypted["iv"]), "big")
        assert not iv & (1 << 63)

    def test_encrypt_matches_reference(self):
        name = "m.cross_signing.master"
        encrypted = encrypt_secret(KEY, name, b"secret")
        aes_key, mac_key = reference_hkdf(KEY, name)
        ciphertext = decode_base64(encrypted["ciphertext"])
        expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
        assert decode_base64(encrypted["mac"]) == expected_mac

    def test_decrypt_wrong_key(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")

        with pytest.raises(ValueError, match="MAC check failed"):
            decrypt_secret(bytes(32), "m.cross_signing.master", encrypted)

    def test_decrypt_wrong_name(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")

        with pytest.raises(ValueError, match="MAC check failed"):
            decrypt_secret(KEY, "m.cross_signing.self_signing", encrypted)

    def test_decrypt_tampered(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")
        ciphertext = bytearray(decode_base64(encrypted["ciphertext"]))
        ciphertext[0] ^= 1
        encrypted["ciphertext"] = encode_base64(bytes(ciphertext))

        with pytest.raises(ValueError, match="MAC check failed"):
            decrypt_secret(KEY, "m.cross_signing.master", encrypted)

    def test_decrypt_malformed(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")
        del encrypted["mac"]

        with pytest.raises(ValueError, match="Malformed encrypted secret"):
            decrypt_secret(KEY, "m.cross_signing.master", encrypted)

        with pytest.raises(ValueError, match="Malformed encrypted secret"):
            decrypt_secret(KEY, "m.cross_signing.master", {"iv": None})

    def test_decrypt_accepts_padded_base64(self):
        encrypted = encrypt_secret(KEY, "m.cross_signing.master", b"secret")
        padded = {k: v + "=" * (-len(v) % 4) for k, v in encrypted.items()}
        assert decrypt_secret(KEY, "m.cross_signing.master", padded) == b"secret"


class TestSecretStorageKeyInfo:
    def test_from_dict(self):
        info = SecretStorageKeyInfo.from_dict(
            "key_id",
            {
                "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
                "name": "Recovery key",
                "iv": KEY_INFO_IV,
                "mac": KEY_INFO_MAC,
            },
        )
        assert info.key_id == "key_id"
        assert info.name == "Recovery key"
        assert info.passphrase is None
        assert info.check_key(KEY)
        assert not info.check_key(bytes(32))

    def test_from_dict_unsupported_algorithm(self):
        with pytest.raises(ValueError, match="Unsupported secret storage algorithm"):
            SecretStorageKeyInfo.from_dict("key_id", {"algorithm": "m.foo"})

    def test_rust_sdk_base58_vector(self):
        info = SecretStorageKeyInfo.from_dict(
            "bmur2d9ypPUH1msSwCxQOJkuKRmJI55e", RUST_SDK_BASE58_KEY_INFO["content"]
        )
        key = decode_recovery_key(RUST_SDK_BASE58_KEY_INFO["recovery_key"])
        assert info.check_key(key)

    def test_rust_sdk_passphrase_vector(self):
        info = SecretStorageKeyInfo.from_dict(
            "DZkbKc0RtKSq0z8V61w6KBmJCK6OCiIu", RUST_SDK_PASSPHRASE_KEY_INFO["content"]
        )
        key = info.key_from_passphrase(RUST_SDK_PASSPHRASE_KEY_INFO["passphrase"])
        assert info.check_key(key)
        assert not info.check_key(info.key_from_passphrase("It's a secret to nobody"))

    def test_key_from_passphrase_without_parameters(self):
        info = SecretStorageKeyInfo("key_id", "m.secret_storage.v1.aes-hmac-sha2")

        with pytest.raises(ValueError, match="can't be derived"):
            info.key_from_passphrase("passphrase")

    def test_key_from_passphrase_unsupported_algorithm(self):
        info = SecretStorageKeyInfo(
            "key_id",
            "m.secret_storage.v1.aes-hmac-sha2",
            passphrase={"algorithm": "m.scrypt", "salt": "salt", "iterations": 10},
        )

        with pytest.raises(ValueError, match="Unsupported passphrase algorithm"):
            info.key_from_passphrase("passphrase")
