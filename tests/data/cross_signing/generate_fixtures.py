"""Generate the deterministic cross-signing and secret storage fixtures.

Every key is derived from a fixed seed so the fixtures can be regenerated at
any time. The seeds are ``sha256(b"nio-test-<name>")``; the secret storage
key is ``bytes(range(32))``.

Run from the repository root:

    uv run python tests/data/cross_signing/generate_fixtures.py

The script intentionally only uses pycryptodome and the standard library, so
the fixtures are independent from the code under test.
"""

import hashlib
import hmac
import json
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Signature import eddsa
from Crypto.Util import Counter
from unpaddedbase64 import encode_base64

ALICE = "@alice:example.org"
ALICE_DEVICE = "JLAFKJWSCS"
BOB = "@bob:example.org"
BOB_DEVICE = "QWERTZUIOP"

SECRET_STORAGE_KEY = bytes(range(32))
SECRET_STORAGE_KEY_ID = "nio_test_key"
PASSPHRASE = "nio-test-passphrase"
PASSPHRASE_SALT = "MmMsAltyMmMsAltyMmMsAlty"
PASSPHRASE_ITERATIONS = 10

OUT = Path(__file__).parent


def seed(name):
    return hashlib.sha256(f"nio-test-{name}".encode()).digest()


def public_key(seed_bytes):
    key = ECC.construct(curve="Ed25519", seed=seed_bytes)
    return encode_base64(key.public_key().export_key(format="raw"))


def canonical_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sign(seed_bytes, obj):
    unsigned = {k: v for k, v in obj.items() if k not in ("signatures", "unsigned")}
    signer = eddsa.new(ECC.construct(curve="Ed25519", seed=seed_bytes), "rfc8032")
    return encode_base64(signer.sign(canonical_json(unsigned).encode()))


def add_signature(obj, user_id, key_id, seed_bytes):
    obj.setdefault("signatures", {}).setdefault(user_id, {})[key_id] = sign(
        seed_bytes, obj
    )
    return obj


def cross_signing_key(user_id, usage, seed_bytes):
    pk = public_key(seed_bytes)
    return {"user_id": user_id, "usage": [usage], "keys": {f"ed25519:{pk}": pk}}


def device_keys(user_id, device_id, seed_bytes, display_name):
    curve_key = encode_base64(hashlib.sha256(seed_bytes).digest())
    keys = {
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "device_id": device_id,
        "user_id": user_id,
        "keys": {
            f"curve25519:{device_id}": curve_key,
            f"ed25519:{device_id}": public_key(seed_bytes),
        },
    }
    add_signature(keys, user_id, f"ed25519:{device_id}", seed_bytes)
    keys["unsigned"] = {"device_display_name": display_name}
    return keys


def identity(user_id, master_seed, ssk_seed, usk_seed=None):
    master = cross_signing_key(user_id, "master", master_seed)
    ssk = add_signature(
        cross_signing_key(user_id, "self_signing", ssk_seed),
        user_id,
        f"ed25519:{public_key(master_seed)}",
        master_seed,
    )
    usk = None
    if usk_seed:
        usk = add_signature(
            cross_signing_key(user_id, "user_signing", usk_seed),
            user_id,
            f"ed25519:{public_key(master_seed)}",
            master_seed,
        )
    return master, ssk, usk


def hkdf(key, name):
    prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
    info = name.encode()
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + info + b"\x02", hashlib.sha256).digest()
    return t1, t2


def aes_ctr(aes_key, iv, data):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    return AES.new(aes_key, AES.MODE_CTR, counter=ctr).encrypt(data)


def encrypt_secret(name, plaintext, iv, key=SECRET_STORAGE_KEY):
    aes_key, mac_key = hkdf(key, name)
    ciphertext = aes_ctr(aes_key, iv, plaintext)
    return {
        "iv": encode_base64(iv),
        "ciphertext": encode_base64(ciphertext),
        "mac": encode_base64(hmac.new(mac_key, ciphertext, hashlib.sha256).digest()),
    }


def write(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    alice_master, alice_ssk, alice_usk = identity(
        ALICE,
        seed("alice-master"),
        seed("alice-self-signing"),
        seed("alice-user-signing"),
    )
    bob_master, bob_ssk, _ = identity(BOB, seed("bob-master"), seed("bob-self-signing"))

    alice_device = device_keys(
        ALICE, ALICE_DEVICE, seed("alice-device"), "Alice's phone"
    )
    bob_device = device_keys(BOB, BOB_DEVICE, seed("bob-device"), "Bob's laptop")

    # Alice's device signs her master key, her self-signing key signs the device.
    add_signature(alice_master, ALICE, f"ed25519:{ALICE_DEVICE}", seed("alice-device"))
    alice_ssk_id = next(iter(alice_ssk["keys"]))
    add_signature(alice_device, ALICE, alice_ssk_id, seed("alice-self-signing"))

    # Alice verified Bob: her user-signing key signs his master key.
    alice_usk_id = next(iter(alice_usk["keys"]))
    add_signature(bob_master, BOB, f"ed25519:{BOB_DEVICE}", seed("bob-device"))
    add_signature(bob_master, ALICE, alice_usk_id, seed("alice-user-signing"))
    bob_ssk_id = next(iter(bob_ssk["keys"]))
    bob_device_unsigned = json.loads(json.dumps(bob_device))
    add_signature(bob_device, BOB, bob_ssk_id, seed("bob-self-signing"))

    write(
        "keys_query_cross_signing.json",
        {
            "device_keys": {
                ALICE: {ALICE_DEVICE: alice_device},
                BOB: {BOB_DEVICE: bob_device},
            },
            "master_keys": {ALICE: alice_master, BOB: bob_master},
            "self_signing_keys": {ALICE: alice_ssk, BOB: bob_ssk},
            "user_signing_keys": {ALICE: alice_usk},
            "failures": {},
        },
    )

    write(
        "keys_query_bob_unsigned.json",
        {
            "device_keys": {BOB: {BOB_DEVICE: bob_device_unsigned}},
            "master_keys": {BOB: bob_master},
            "self_signing_keys": {BOB: bob_ssk},
            "failures": {},
        },
    )

    # Bob reset his cross-signing keys.
    bob_master2, bob_ssk2, _ = identity(
        BOB, seed("bob-master-2"), seed("bob-self-signing-2")
    )
    bob_device2 = device_keys(BOB, BOB_DEVICE, seed("bob-device"), "Bob's laptop")
    add_signature(
        bob_device2, BOB, next(iter(bob_ssk2["keys"])), seed("bob-self-signing-2")
    )
    write(
        "keys_query_bob_new_master.json",
        {
            "device_keys": {BOB: {BOB_DEVICE: bob_device2}},
            "master_keys": {BOB: bob_master2},
            "self_signing_keys": {BOB: bob_ssk2},
            "failures": {},
        },
    )

    # Secret storage: key description checked with the recovery key, secrets
    # hold the base64 encoded seeds of Alice's cross-signing keys.
    write("default_key.json", {"key": SECRET_STORAGE_KEY_ID})
    check = encrypt_secret("", b"\x00" * 32, bytes(range(16)))
    write(
        "secret_storage_key.json",
        {
            "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
            "name": "nio test key",
            "iv": check["iv"],
            "mac": check["mac"],
        },
    )
    passphrase_key = PBKDF2(
        PASSPHRASE.encode(),
        PASSPHRASE_SALT.encode(),
        32,
        PASSPHRASE_ITERATIONS,
        hmac_hash_module=SHA512,
    )
    check = encrypt_secret("", b"\x00" * 32, bytes(range(16, 32)), passphrase_key)
    write(
        "secret_storage_key_passphrase.json",
        {
            "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
            "iv": check["iv"],
            "mac": check["mac"],
            "passphrase": {
                "algorithm": "m.pbkdf2",
                "salt": PASSPHRASE_SALT,
                "iterations": PASSPHRASE_ITERATIONS,
            },
        },
    )
    for name, usage in (
        ("m.cross_signing.master", "master"),
        ("m.cross_signing.self_signing", "self-signing"),
        ("m.cross_signing.user_signing", "user-signing"),
    ):
        iv = hashlib.sha256(name.encode()).digest()[:16]
        iv = (int.from_bytes(iv, "big") & ~(1 << 63)).to_bytes(16, "big")
        plaintext = encode_base64(seed(f"alice-{usage}")).encode()
        file_name = f"secret_{usage.replace('-', '_')}"
        write(
            f"{file_name}.json",
            {"encrypted": {SECRET_STORAGE_KEY_ID: encrypt_secret(name, plaintext, iv)}},
        )
        write(
            f"{file_name}_passphrase.json",
            {
                "encrypted": {
                    SECRET_STORAGE_KEY_ID: encrypt_secret(
                        name, plaintext, iv, passphrase_key
                    )
                }
            },
        )

    write(
        "uiaa_401.json",
        {
            "session": "xxxxxxyz",
            "flows": [{"stages": ["m.login.password"]}],
            "params": {},
        },
    )


if __name__ == "__main__":
    main()
