import json
from os import path

import pytest
from hypothesis import given
from hypothesis.strategies import binary

from nio import EncryptionError
from nio.crypto import Olm
from nio.crypto.key_export import (decrypt, decrypt_and_read, encrypt,
                                   encrypt_and_save)
from nio.store import DefaultStore

TEST_ROOM = "!test:example.org"

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

    def test_export(self, tempdir):
        user_id = "ephemeral"
        device_id = "DEVICEID"

        file = path.join(tempdir, "keys_file")

        store = DefaultStore(user_id, device_id, tempdir, "")
        olm = Olm(user_id, device_id, store)
        olm.create_outbound_group_session(TEST_ROOM)

        out_session = olm.outbound_group_sessions[TEST_ROOM]

        assert olm.inbound_group_store.get(
                TEST_ROOM,
                olm.account.identity_keys["curve25519"],
                out_session.id
        )
        olm.export_keys(file, "pass")

        alice_store = DefaultStore("alice", device_id, tempdir, "")
        alice = Olm("alice", device_id, alice_store)

        assert not alice.inbound_group_store.get(
                TEST_ROOM,
                olm.account.identity_keys["curve25519"],
                out_session.id
        )

        alice.import_keys(file, "pass")

        assert alice.inbound_group_store.get(
                TEST_ROOM,
                olm.account.identity_keys["curve25519"],
                out_session.id
        )

    def test_unencrypted_import(self, tempdir):
        device_id = "DEVICEID"
        file = path.join(tempdir, "keys_file")

        with open(file, "w") as f:
            f.write("{}")

        alice_store = DefaultStore("alice", device_id, tempdir, "")
        alice = Olm("alice", device_id, alice_store)
        with pytest.raises(EncryptionError):
            alice.import_keys(file, "pass")

    def test_invalid_json(self, tempdir):
        device_id = "DEVICEID"
        file = path.join(tempdir, "keys_file")

        encrypt_and_save(b"{sessions: [{}]}", file, "pass", count=10)

        alice_store = DefaultStore("alice", device_id, tempdir, "")
        alice = Olm("alice", device_id, alice_store)

        with pytest.raises(EncryptionError):
            alice.import_keys(file, "pass")

    def test_invalid_json_schema(self, tempdir):
        device_id = "DEVICEID"
        file = path.join(tempdir, "keys_file")

        payload = {
            "sessions": [
                {
                    "algorithm": "test"
                }
            ]
        }

        encrypt_and_save(
            json.dumps(payload).encode(),
            file,
            "pass",
            count=10
        )

        alice_store = DefaultStore("alice", device_id, tempdir, "")
        alice = Olm("alice", device_id, alice_store)

        with pytest.raises(EncryptionError):
            alice.import_keys(file, "pass")
