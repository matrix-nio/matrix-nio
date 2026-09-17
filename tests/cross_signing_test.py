import copy
import hashlib
import json
from pathlib import Path

import pytest
import vodozemac
from unpaddedbase64 import decode_base64

from nio.api import Api
from nio.crypto import (
    CrossSigningKey,
    CrossSigningPrivateKeys,
    Olm,
    UserIdentity,
)
from nio.crypto.cross_signing import (
    public_key_from_seed,
    sign_json,
    verify_signed_json,
)
from nio.responses import KeysQueryResponse

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"
BOB_ID = "@bob:example.org"
BOB_DEVICE_ID = "QWERTZUIOP"
CAROL_ID = "@carol:example.org"

FIXTURES = Path("tests/data/cross_signing")


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def seed(name):
    """The fixture seeds, see tests/data/cross_signing/generate_fixtures.py."""
    return hashlib.sha256(f"nio-test-{name}".encode()).digest()


def alice_private_keys():
    return CrossSigningPrivateKeys(
        seed("alice-master"), seed("alice-self-signing"), seed("alice-user-signing")
    )


def vodozemac_verify(json_dict, user_id, key_id, public_key):
    unsigned = {
        k: v for k, v in json_dict.items() if k not in ("signatures", "unsigned")
    }
    key = vodozemac.Ed25519PublicKey.from_base64(public_key)
    signature = vodozemac.Ed25519Signature.from_base64(
        json_dict["signatures"][user_id][key_id]
    )
    key.verify_signature(Api.to_canonical_json(unsigned).encode(), signature)


class TestSigning:
    def test_public_key_from_seed(self):
        fixture = load_fixture("keys_query_cross_signing.json")
        master = fixture["master_keys"][ALICE_ID]
        public_key = public_key_from_seed(seed("alice-master"))
        assert master["keys"] == {f"ed25519:{public_key}": public_key}

    def test_sign_json(self):
        json_dict = {"b": 2, "a": "ü", "signatures": {"x": {}}, "unsigned": {"y": 1}}
        signature = sign_json(seed("alice-master"), json_dict)
        public_key = public_key_from_seed(seed("alice-master"))

        signed = {"a": "ü", "b": 2, "signatures": {ALICE_ID: {"key": signature}}}
        vodozemac_verify(signed, ALICE_ID, "key", public_key)
        assert verify_signed_json(signed, ALICE_ID, "key", public_key)

        # The signature covers the object without signatures and unsigned.
        signed["unsigned"] = {"other": True}
        assert verify_signed_json(signed, ALICE_ID, "key", public_key)

        signed["a"] = "u"
        assert not verify_signed_json(signed, ALICE_ID, "key", public_key)

    def test_verify_signed_json_does_not_mutate(self):
        fixture = load_fixture("keys_query_cross_signing.json")
        payload = fixture["device_keys"][ALICE_ID][ALICE_DEVICE_ID]
        original = copy.deepcopy(payload)
        key = payload["keys"][f"ed25519:{ALICE_DEVICE_ID}"]

        assert verify_signed_json(payload, ALICE_ID, f"ed25519:{ALICE_DEVICE_ID}", key)
        assert payload == original

    def test_verify_signed_json_missing_signature(self):
        public_key = public_key_from_seed(seed("alice-master"))
        assert not verify_signed_json({}, ALICE_ID, "key", public_key)
        assert not verify_signed_json({"signatures": {}}, ALICE_ID, "key", public_key)
        assert not verify_signed_json(
            {"signatures": {ALICE_ID: {}}}, ALICE_ID, "key", public_key
        )
        assert not verify_signed_json(
            {"signatures": {ALICE_ID: {"key": "invalid"}}}, ALICE_ID, "key", public_key
        )

    def test_verify_signed_json_invalid_key(self):
        signed = {"a": 1, "signatures": {ALICE_ID: {"key": "abc"}}}
        assert not verify_signed_json(signed, ALICE_ID, "key", "not a key")


class TestCrossSigningKey:
    def test_from_dict(self):
        fixture = load_fixture("keys_query_cross_signing.json")
        key = CrossSigningKey.from_dict(fixture["self_signing_keys"][BOB_ID])

        assert key.user_id == BOB_ID
        assert key.usage == ["self_signing"]
        assert key.key_id == f"ed25519:{key.public_key}"
        assert key.as_dict() == fixture["self_signing_keys"][BOB_ID]

        master = CrossSigningKey.from_dict(fixture["master_keys"][BOB_ID])
        assert key.is_signed_by(BOB_ID, master.key_id, master.public_key)
        assert not master.is_signed_by(BOB_ID, key.key_id, key.public_key)

    def test_as_dict_without_signatures(self):
        key = CrossSigningKey(ALICE_ID, ["master"], "abc")
        assert key.as_dict() == {
            "user_id": ALICE_ID,
            "usage": ["master"],
            "keys": {"ed25519:abc": "abc"},
        }

    @pytest.mark.parametrize(
        "keys",
        [
            {},
            {"ed25519:abc": "abc", "ed25519:def": "def"},
            {"ed25519:abc": "def"},
            {"curve25519:abc": "abc"},
        ],
    )
    def test_from_dict_invalid(self, keys):
        key_dict = {"user_id": ALICE_ID, "usage": ["master"], "keys": keys}

        with pytest.raises(ValueError):
            CrossSigningKey.from_dict(key_dict)


class TestCrossSigningPrivateKeys:
    def test_generate(self):
        keys = CrossSigningPrivateKeys.generate()
        assert keys
        assert keys.master and keys.self_signing and keys.user_signing
        assert keys.master != keys.self_signing
        assert not CrossSigningPrivateKeys()

    def test_public_keys(self):
        keys = alice_private_keys()
        fixture = load_fixture("keys_query_cross_signing.json")

        for usage, section in (
            ("master", "master_keys"),
            ("self_signing", "self_signing_keys"),
            ("user_signing", "user_signing_keys"),
        ):
            public_key = keys.public_key(usage)
            assert fixture[section][ALICE_ID]["keys"] == {
                f"ed25519:{public_key}": public_key
            }

        assert CrossSigningPrivateKeys().public_key("master") is None

    def test_sign(self):
        keys = CrossSigningPrivateKeys(self_signing=seed("alice-self-signing"))
        json_dict = {"device_id": ALICE_DEVICE_ID}
        signature = keys.sign("self_signing", json_dict)
        signed = {
            **json_dict,
            "signatures": {ALICE_ID: {"ed25519:key": signature}},
        }
        vodozemac_verify(
            signed, ALICE_ID, "ed25519:key", keys.public_key("self_signing")
        )

        with pytest.raises(ValueError, match="master key is not known"):
            keys.sign("master", json_dict)

    def test_as_identity(self):
        keys = alice_private_keys()
        identity = keys.as_identity(ALICE_ID)

        assert identity.user_id == ALICE_ID
        assert identity.master_key.usage == ["master"]
        assert identity.master_key.signatures == {}

        for key in (identity.self_signing_key, identity.user_signing_key):
            assert key.is_signed_by(
                ALICE_ID, identity.master_key.key_id, identity.master_key.public_key
            )
            vodozemac_verify(
                key.as_dict(),
                ALICE_ID,
                identity.master_key.key_id,
                identity.master_key.public_key,
            )

        assert len(identity.keys) == 3

        identity = CrossSigningPrivateKeys(
            master=seed("alice-master"), self_signing=seed("alice-self-signing")
        ).as_identity(ALICE_ID)
        assert identity.user_signing_key is None
        assert len(identity.keys) == 2

    def test_as_identity_without_master(self):
        with pytest.raises(ValueError, match="master key is not known"):
            CrossSigningPrivateKeys(self_signing=seed("x")).as_identity(ALICE_ID)


class TestOlm:
    def keys_query(self, olm, name, mutate=None):
        parsed_dict = load_fixture(name)

        if mutate:
            mutate(parsed_dict)

        response = KeysQueryResponse.from_dict(parsed_dict)
        assert isinstance(response, KeysQueryResponse)
        olm.handle_response(response)
        return response

    def test_identities(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")

        assert set(olm_machine.user_identities) == {ALICE_ID, BOB_ID}

        alice = olm_machine.user_identities[ALICE_ID]
        assert isinstance(alice, UserIdentity)
        assert alice.master_key.usage == ["master"]
        assert alice.self_signing_key.usage == ["self_signing"]
        assert alice.user_signing_key.usage == ["user_signing"]

        bob = olm_machine.user_identities[BOB_ID]
        assert bob.self_signing_key
        assert bob.user_signing_key is None

        # The identities are persisted.
        loaded = olm_machine.store.load_user_identities()
        assert loaded == olm_machine.user_identities

    def test_device_cross_signed(self, olm_machine):
        response = self.keys_query(olm_machine, "keys_query_cross_signing.json")

        bob_device = olm_machine.device_store[BOB_ID][BOB_DEVICE_ID]
        assert bob_device.cross_signed
        assert BOB_DEVICE_ID in response.changed[BOB_ID]

        loaded = olm_machine.store.load_device_keys()
        assert loaded[BOB_ID][BOB_DEVICE_ID].cross_signed

        # A repeated query doesn't change anything.
        response = self.keys_query(olm_machine, "keys_query_cross_signing.json")
        assert not response.changed

        # The self-signing signature disappears.
        response = self.keys_query(olm_machine, "keys_query_bob_unsigned.json")
        assert not bob_device.cross_signed
        assert BOB_DEVICE_ID in response.changed[BOB_ID]
        assert not olm_machine.store.load_device_keys()[BOB_ID][
            BOB_DEVICE_ID
        ].cross_signed

    def test_device_not_cross_signed(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_bob_unsigned.json")
        assert not olm_machine.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed

    def test_device_forged_signature(self, olm_machine):
        def mutate(parsed_dict):
            device = parsed_dict["device_keys"][BOB_ID][BOB_DEVICE_ID]
            device["unsigned"]["device_display_name"] = "Bob's laptop"
            ssk_id = next(iter(parsed_dict["self_signing_keys"][BOB_ID]["keys"]))
            device["keys"]["curve25519:" + BOB_DEVICE_ID] = "A" * 43
            # Re-sign with the device key so the device is accepted at all.
            device["signatures"][BOB_ID][f"ed25519:{BOB_DEVICE_ID}"] = sign_json(
                seed("bob-device"), device
            )
            assert ssk_id in device["signatures"][BOB_ID]

        self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)
        assert not olm_machine.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed

    def test_self_signing_key_without_master_signature(self, olm_machine, caplog):
        def mutate(parsed_dict):
            del parsed_dict["self_signing_keys"][BOB_ID]["signatures"]

        self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)

        bob = olm_machine.user_identities[BOB_ID]
        assert bob.self_signing_key is None
        assert not olm_machine.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed
        assert "Signature verification failed for the self_signing key" in caplog.text

    def test_invalid_master_key(self, olm_machine, caplog):
        def mutate(parsed_dict):
            parsed_dict["master_keys"][BOB_ID]["keys"]["ed25519:other"] = "other"

        self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)
        assert BOB_ID not in olm_machine.user_identities
        assert "Invalid master key for user @bob:example.org" in caplog.text

    def test_mismatched_master_key(self, olm_machine, caplog):
        def mutate(parsed_dict):
            parsed_dict["master_keys"][BOB_ID]["user_id"] = CAROL_ID

        self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)
        assert BOB_ID not in olm_machine.user_identities
        assert "Mismatch in master key payload of user @bob:example.org" in caplog.text

    def test_master_key_change(self, olm_machine, caplog):
        response = self.keys_query(olm_machine, "keys_query_cross_signing.json")
        assert response.changed_identities == {}
        old_master = olm_machine.user_identities[BOB_ID].master_key
        assert olm_machine.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed

        response = self.keys_query(olm_machine, "keys_query_bob_new_master.json")
        new_master = olm_machine.user_identities[BOB_ID].master_key
        assert new_master.public_key != old_master.public_key
        assert "Master key has changed for user @bob:example.org" in caplog.text
        assert response.changed_identities == {
            BOB_ID: olm_machine.user_identities[BOB_ID]
        }

        # The device is signed by the new self-signing key.
        assert olm_machine.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed
        assert olm_machine.store.load_user_identities()[BOB_ID].master_key == new_master

    def test_own_master_key_change(self, olm_machine, caplog):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")
        olm_machine.cross_signing_private_keys = alice_private_keys()
        olm_machine.store.save_cross_signing_private_keys(alice_private_keys())
        assert olm_machine.is_user_verified(ALICE_ID)

        def mutate(parsed_dict):
            # Alice reset her keys, e.g. in another client.
            alice_seeds = CrossSigningPrivateKeys(seed("x"), seed("y"), seed("z"))
            identity = alice_seeds.as_identity(ALICE_ID)
            parsed_dict["master_keys"][ALICE_ID] = identity.master_key.as_dict()
            parsed_dict["self_signing_keys"][
                ALICE_ID
            ] = identity.self_signing_key.as_dict()
            parsed_dict["user_signing_keys"][
                ALICE_ID
            ] = identity.user_signing_key.as_dict()

        response = self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)
        assert ALICE_ID in response.changed_identities
        assert "Discarding the stored private cross-signing keys" in caplog.text
        assert not olm_machine.cross_signing_private_keys
        assert not olm_machine.store.load_cross_signing_private_keys()
        assert not olm_machine.is_user_verified(ALICE_ID)
        # Bob's master key is signed by the old user-signing key.
        assert not olm_machine.is_user_verified(BOB_ID)

    def test_user_signing_key_of_other_users_ignored(self, olm_machine):
        def mutate(parsed_dict):
            parsed_dict["user_signing_keys"][BOB_ID] = parsed_dict["user_signing_keys"][
                ALICE_ID
            ]

        self.keys_query(olm_machine, "keys_query_cross_signing.json", mutate)
        assert olm_machine.user_identities[BOB_ID].user_signing_key is None

    def test_private_keys_repr(self):
        keys = alice_private_keys()
        assert seed("alice-master").hex()[:8] not in repr(keys)
        assert "master" not in repr(keys)

    def test_is_user_verified(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")

        # Without private keys nothing is verified, not even ourselves.
        assert not olm_machine.is_user_verified(ALICE_ID)
        assert not olm_machine.is_user_verified(BOB_ID)
        assert not olm_machine.is_user_verified(CAROL_ID)

        olm_machine.cross_signing_private_keys = alice_private_keys()
        assert olm_machine.is_user_verified(ALICE_ID)
        # Bob's master key is signed by Alice's user-signing key.
        assert olm_machine.is_user_verified(BOB_ID)
        assert not olm_machine.is_user_verified(CAROL_ID)

        # Bob reset his keys, the new master key isn't signed by us.
        self.keys_query(olm_machine, "keys_query_bob_new_master.json")
        assert not olm_machine.is_user_verified(BOB_ID)

    def test_is_user_verified_with_self_signing_key_only(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")

        # The self-signing key alone doesn't prove that the master key is
        # ours.
        olm_machine.cross_signing_private_keys = CrossSigningPrivateKeys(
            self_signing=seed("alice-self-signing")
        )
        assert not olm_machine.is_user_verified(ALICE_ID)
        assert not olm_machine.is_user_verified(BOB_ID)

    def test_is_user_verified_without_user_signing_key(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")

        olm_machine.cross_signing_private_keys = CrossSigningPrivateKeys(
            master=seed("alice-master")
        )
        assert olm_machine.is_user_verified(ALICE_ID)
        # Trusting Bob only needs our published user-signing key.
        assert olm_machine.is_user_verified(BOB_ID)

        olm_machine.user_identities[ALICE_ID].user_signing_key = None
        assert not olm_machine.is_user_verified(BOB_ID)

    def test_is_user_verified_with_wrong_master_key(self, olm_machine):
        self.keys_query(olm_machine, "keys_query_cross_signing.json")

        olm_machine.cross_signing_private_keys = CrossSigningPrivateKeys(
            master=seed("bob-master"), user_signing=seed("alice-user-signing")
        )
        assert not olm_machine.is_user_verified(ALICE_ID)
        assert not olm_machine.is_user_verified(BOB_ID)

    def test_is_device_payload_cross_signed(self, olm_machine):
        fixture = load_fixture("keys_query_cross_signing.json")
        payload = fixture["device_keys"][ALICE_ID][ALICE_DEVICE_ID]

        assert not olm_machine.is_device_payload_cross_signed(ALICE_ID, payload)

        self.keys_query(olm_machine, "keys_query_cross_signing.json")
        assert olm_machine.is_device_payload_cross_signed(ALICE_ID, payload)
        assert not olm_machine.is_device_payload_cross_signed(BOB_ID, payload)

        del payload["signatures"][ALICE_ID][
            olm_machine.user_identities[ALICE_ID].self_signing_key.key_id
        ]
        assert not olm_machine.is_device_payload_cross_signed(ALICE_ID, payload)

    def test_own_device_keys(self, olm_machine):
        device_keys = olm_machine.own_device_keys()
        assert device_keys["device_id"] == olm_machine.device_id
        assert device_keys["user_id"] == olm_machine.user_id
        assert olm_machine.verify_json(
            device_keys,
            olm_machine.account.identity_keys["ed25519"],
            olm_machine.user_id,
            olm_machine.device_id,
        )
        assert "signatures" in device_keys

    def test_verify_json_regression(self, olm_machine):
        parsed_dict = load_fixture("../keys_query.json")
        payload = parsed_dict["device_keys"][ALICE_ID][ALICE_DEVICE_ID]
        key = payload["keys"][f"ed25519:{ALICE_DEVICE_ID}"]
        assert olm_machine.verify_json(payload, key, ALICE_ID, ALICE_DEVICE_ID)
        assert not olm_machine.verify_json(payload, key, ALICE_ID, "OTHER")
        assert not olm_machine.verify_json(payload, key, BOB_ID, ALICE_DEVICE_ID)

    def test_private_keys_persisted(self, olm_machine):
        keys = alice_private_keys()
        olm_machine.store.save_cross_signing_private_keys(keys)

        olm = Olm(olm_machine.user_id, olm_machine.device_id, olm_machine.store)
        assert olm.cross_signing_private_keys == keys
        assert decode_base64(olm.cross_signing_private_keys.public_key("master"))
