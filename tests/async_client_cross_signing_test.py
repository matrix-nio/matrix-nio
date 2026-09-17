import copy
import hashlib
import json
from pathlib import Path

import pytest
import pytest_asyncio
from unpaddedbase64 import encode_base64
from yarl import URL

from nio import (
    AsyncClient,
    AsyncClientConfig,
    GetAccountDataError,
    GetAccountDataResponse,
    KeysDeviceSigningUploadAuthResponse,
    KeysDeviceSigningUploadError,
    KeysDeviceSigningUploadResponse,
    KeysQueryError,
    KeysSignaturesUploadError,
    KeysSignaturesUploadResponse,
    LocalProtocolError,
    LoginResponse,
)
from nio.api import MATRIX_API_PATH_V3
from nio.crypto import CrossSigningPrivateKeys
from nio.crypto.cross_signing import sign_json, verify_signed_json
from nio.crypto.ssss import SecretStorageKeyInfo, encrypt_secret

BASE_URL_V3 = f"https://example.org{MATRIX_API_PATH_V3}"

ALICE_ID = "@alice:example.org"
ALICE_DEVICE_ID = "JLAFKJWSCS"
BOB_ID = "@bob:example.org"
BOB_DEVICE_ID = "QWERTZUIOP"

RECOVERY_KEY = "EsSz ykH7 LCZx 7Cae cmKD wcmY JRXi Ybtu 8iQ3 t8Ez nRwK pUY1"
PASSPHRASE = "nio-test-passphrase"
KEY_ID = "nio_test_key"

FIXTURES = Path("tests/data/cross_signing")


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text())


def seed(name):
    return hashlib.sha256(f"nio-test-{name}".encode()).digest()


def alice_private_keys():
    return CrossSigningPrivateKeys(
        seed("alice-master"), seed("alice-self-signing"), seed("alice-user-signing")
    )


def account_data_url(event_type):
    return f"{BASE_URL_V3}/user/{ALICE_ID}/account_data/{event_type}"


def request_bodies(aioresponse, method, url):
    return [
        json.loads(call.kwargs["data"])
        for call in aioresponse.requests[(method, URL(url))]
    ]


@pytest_asyncio.fixture
async def alice(tempdir):
    client = AsyncClient(
        "https://example.org",
        ALICE_ID,
        ALICE_DEVICE_ID,
        tempdir,
        config=AsyncClientConfig(max_timeouts=3),
    )
    await client.receive_response(LoginResponse(ALICE_ID, ALICE_DEVICE_ID, "abc123"))
    yield client
    await client.close()


@pytest.mark.asyncio
class TestClass:
    def mock_secret_storage(self, aioresponse, key_info="secret_storage_key.json"):
        aioresponse.get(
            account_data_url("m.secret_storage.default_key"),
            status=200,
            payload=load_fixture("default_key.json"),
        )
        aioresponse.get(
            account_data_url(f"m.secret_storage.key.{KEY_ID}"),
            status=200,
            payload=load_fixture(key_info),
        )

    def mock_secrets(
        self,
        aioresponse,
        usages=("master", "self_signing", "user_signing"),
        suffix="",
    ):
        for usage in ("master", "self_signing", "user_signing"):
            if usage in usages:
                aioresponse.get(
                    account_data_url(f"m.cross_signing.{usage}"),
                    status=200,
                    payload=load_fixture(f"secret_{usage}{suffix}.json"),
                )
            else:
                aioresponse.get(
                    account_data_url(f"m.cross_signing.{usage}"),
                    status=404,
                    payload={"errcode": "M_NOT_FOUND", "error": "Not found"},
                )

    def mock_keys_query(self, aioresponse, payload=None, status=200):
        aioresponse.post(
            f"{BASE_URL_V3}/keys/query",
            status=status,
            payload=payload or load_fixture("keys_query_cross_signing.json"),
        )

    async def import_keys(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(aioresponse)
        keys = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert isinstance(keys, CrossSigningPrivateKeys)
        return keys

    async def test_get_account_data(self, alice, aioresponse):
        aioresponse.get(
            account_data_url("m.secret_storage.default_key"),
            status=200,
            payload={"key": KEY_ID},
        )
        aioresponse.get(
            account_data_url("m.missing"),
            status=404,
            payload={"errcode": "M_NOT_FOUND", "error": "Not found"},
        )

        resp = await alice.get_account_data("m.secret_storage.default_key")
        assert isinstance(resp, GetAccountDataResponse)
        assert resp.event_type == "m.secret_storage.default_key"
        assert resp.content == {"key": KEY_ID}

        resp = await alice.get_account_data("m.missing")
        assert isinstance(resp, GetAccountDataError)
        assert resp.status_code == "M_NOT_FOUND"

    async def test_keys_device_signing_upload(self, alice, aioresponse):
        url = f"{BASE_URL_V3}/keys/device_signing/upload"
        aioresponse.post(url, status=401, payload=load_fixture("uiaa_401.json"))
        aioresponse.post(url, status=200, payload={})
        aioresponse.post(
            url,
            status=403,
            payload={"errcode": "M_FORBIDDEN", "error": "Key ID in use"},
        )

        master_key = alice_private_keys().as_identity(ALICE_ID).master_key.as_dict()

        resp = await alice.keys_device_signing_upload(master_key)
        assert isinstance(resp, KeysDeviceSigningUploadAuthResponse)
        assert resp.session == "xxxxxxyz"

        auth = {"type": "m.login.password", "session": resp.session}
        resp = await alice.keys_device_signing_upload(master_key, auth=auth)
        assert isinstance(resp, KeysDeviceSigningUploadResponse)

        resp = await alice.keys_device_signing_upload(master_key)
        assert isinstance(resp, KeysDeviceSigningUploadError)

        bodies = request_bodies(aioresponse, "POST", url)
        assert bodies[0] == {"master_key": master_key}
        assert bodies[1] == {"master_key": master_key, "auth": auth}

    async def test_keys_signatures_upload(self, alice, aioresponse):
        url = f"{BASE_URL_V3}/keys/signatures/upload"
        failures = {ALICE_ID: {"DEVICE": {"errcode": "M_INVALID_SIGNATURE"}}}
        aioresponse.post(url, status=200, payload={"failures": failures})
        aioresponse.post(
            url, status=403, payload={"errcode": "M_FORBIDDEN", "error": "No"}
        )

        signatures = {ALICE_ID: {"DEVICE": {"signatures": {}}}}
        resp = await alice.keys_signatures_upload(signatures)
        assert isinstance(resp, KeysSignaturesUploadResponse)
        assert resp.failures == failures
        assert request_bodies(aioresponse, "POST", url) == [signatures]

        resp = await alice.keys_signatures_upload(signatures)
        assert isinstance(resp, KeysSignaturesUploadError)

    async def test_get_secret_storage_default_key(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)

        key_info = await alice.get_secret_storage_default_key()
        assert isinstance(key_info, SecretStorageKeyInfo)
        assert key_info.key_id == KEY_ID
        assert key_info.name == "nio test key"
        assert key_info.iv and key_info.mac

    async def test_get_secret_storage_default_key_errors(self, alice, aioresponse):
        url = account_data_url("m.secret_storage.default_key")
        aioresponse.get(
            url, status=404, payload={"errcode": "M_NOT_FOUND", "error": "Not found"}
        )
        resp = await alice.get_secret_storage_default_key()
        assert isinstance(resp, GetAccountDataError)

        aioresponse.get(url, status=200, payload={})
        with pytest.raises(LocalProtocolError, match="no default secret storage key"):
            await alice.get_secret_storage_default_key()

        aioresponse.get(url, status=200, payload={"key": KEY_ID})
        aioresponse.get(
            account_data_url(f"m.secret_storage.key.{KEY_ID}"),
            status=404,
            payload={"errcode": "M_NOT_FOUND", "error": "Not found"},
        )
        resp = await alice.get_secret_storage_default_key()
        assert isinstance(resp, GetAccountDataError)

        aioresponse.get(url, status=200, payload={"key": KEY_ID})
        aioresponse.get(
            account_data_url(f"m.secret_storage.key.{KEY_ID}"),
            status=200,
            payload={"algorithm": "m.secret_storage.v2"},
        )
        with pytest.raises(ValueError, match="Unsupported secret storage algorithm"):
            await alice.get_secret_storage_default_key()

    async def test_get_secret(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse, usages=("self_signing",))
        key_info = await alice.get_secret_storage_default_key()
        key = bytes(range(32))

        secret = await alice.get_secret("m.cross_signing.self_signing", key, key_info)
        assert secret == encode_base64(seed("alice-self-signing")).encode()

        resp = await alice.get_secret("m.cross_signing.master", key, key_info)
        assert isinstance(resp, GetAccountDataError)

        aioresponse.get(
            account_data_url("m.cross_signing.self_signing"),
            status=200,
            payload={"encrypted": {"other_key": {}}},
        )
        with pytest.raises(LocalProtocolError, match="isn't encrypted with the key"):
            await alice.get_secret("m.cross_signing.self_signing", key, key_info)

        aioresponse.get(
            account_data_url("m.cross_signing.self_signing"),
            status=200,
            payload=load_fixture("secret_self_signing.json"),
        )
        with pytest.raises(ValueError, match="MAC check failed"):
            await alice.get_secret("m.cross_signing.self_signing", bytes(32), key_info)

    async def test_import_from_recovery_key(self, alice, aioresponse):
        assert not alice.olm.cross_signing_private_keys
        assert not alice.is_user_verified(ALICE_ID)

        keys = await self.import_keys(alice, aioresponse)
        assert keys == alice_private_keys()
        assert alice.olm.cross_signing_private_keys == keys
        assert alice.store.load_cross_signing_private_keys() == keys

        assert alice.is_user_verified(ALICE_ID)
        assert alice.is_user_verified(BOB_ID)
        assert alice.user_identities[ALICE_ID].user_signing_key
        assert alice.device_store[BOB_ID][BOB_DEVICE_ID].cross_signed

    async def test_import_from_passphrase(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse, "secret_storage_key_passphrase.json")
        self.mock_secrets(aioresponse, suffix="_passphrase")
        self.mock_keys_query(aioresponse)

        keys = await alice.import_cross_signing_keys_from_passphrase(PASSPHRASE)
        assert keys == alice_private_keys()
        assert alice.is_user_verified(ALICE_ID)

    async def test_import_wrong_passphrase(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse, "secret_storage_key_passphrase.json")

        with pytest.raises(ValueError, match="doesn't match"):
            await alice.import_cross_signing_keys_from_passphrase("wrong")

    async def test_import_from_passphrase_error(self, alice, aioresponse):
        aioresponse.get(
            account_data_url("m.secret_storage.default_key"),
            status=404,
            payload={"errcode": "M_NOT_FOUND", "error": "Not found"},
        )
        resp = await alice.import_cross_signing_keys_from_passphrase(PASSPHRASE)
        assert isinstance(resp, GetAccountDataError)

    async def test_import_wrong_recovery_key(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        wrong_key = "EsTj 3yST y93F SLpB jJsz eAXc 2XzA ygD3 w69H fGaN TKBj jXEd"

        with pytest.raises(ValueError, match="doesn't match"):
            await alice.import_cross_signing_keys_from_recovery_key(wrong_key)

        with pytest.raises(ValueError, match="Invalid recovery key"):
            await alice.import_cross_signing_keys_from_recovery_key("EsSz")

    async def test_import_without_secret_storage(self, alice, aioresponse):
        aioresponse.get(
            account_data_url("m.secret_storage.default_key"),
            status=404,
            payload={"errcode": "M_NOT_FOUND", "error": "Not found"},
        )
        resp = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert isinstance(resp, GetAccountDataError)

    async def test_import_self_signing_key_only(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse, usages=("self_signing",))
        self.mock_keys_query(aioresponse)

        keys = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert keys == CrossSigningPrivateKeys(self_signing=seed("alice-self-signing"))
        assert not alice.is_user_verified(ALICE_ID)

    async def test_import_without_secrets(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse, usages=())

        with pytest.raises(LocalProtocolError, match="No cross-signing keys found"):
            await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

    async def test_import_secret_error(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        aioresponse.get(
            account_data_url("m.cross_signing.master"),
            status=403,
            payload={"errcode": "M_FORBIDDEN", "error": "Forbidden"},
        )
        resp = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert isinstance(resp, GetAccountDataError)
        assert resp.status_code == "M_FORBIDDEN"

    async def test_import_keys_query_error(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(
            aioresponse,
            status=500,
            payload={"errcode": "M_UNKNOWN", "error": "Internal error"},
        )
        resp = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert isinstance(resp, KeysQueryError)
        assert not alice.olm.cross_signing_private_keys

    async def test_import_published_keys_mismatch(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(aioresponse, load_fixture("keys_query_bob_unsigned.json"))

        with pytest.raises(LocalProtocolError, match="has no cross-signing keys"):
            await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        payload = load_fixture("keys_query_cross_signing.json")
        payload["master_keys"][ALICE_ID] = payload["master_keys"][BOB_ID]
        payload["self_signing_keys"][ALICE_ID] = payload["self_signing_keys"][BOB_ID]
        del payload["user_signing_keys"][ALICE_ID]
        for key in ("master_keys", "self_signing_keys"):
            payload[key][ALICE_ID] = copy.deepcopy(payload[key][ALICE_ID])
            payload[key][ALICE_ID]["user_id"] = ALICE_ID
        # Bob's self-signing key was signed by Bob's master key.
        payload["self_signing_keys"][ALICE_ID]["signatures"] = {
            ALICE_ID: payload["self_signing_keys"][ALICE_ID]["signatures"][BOB_ID]
        }
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(aioresponse, payload)

        with pytest.raises(LocalProtocolError, match="doesn't match the published"):
            await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        assert not alice.olm.cross_signing_private_keys

    async def test_sign_own_device(self, alice, aioresponse):
        keys = await self.import_keys(alice, aioresponse)
        url = f"{BASE_URL_V3}/keys/signatures/upload"
        aioresponse.post(url, status=200, payload={})

        resp = await alice.sign_own_device()
        assert isinstance(resp, KeysSignaturesUploadResponse)
        assert resp.failures == {}

        identity = alice.user_identities[ALICE_ID]
        (body,) = request_bodies(aioresponse, "POST", url)
        assert set(body) == {ALICE_ID}
        assert set(body[ALICE_ID]) == {ALICE_DEVICE_ID, identity.master_key.public_key}

        device_keys = body[ALICE_ID][ALICE_DEVICE_ID]
        assert device_keys["keys"] == alice.olm.own_device_keys()["keys"]
        assert set(device_keys["signatures"][ALICE_ID]) == {
            identity.self_signing_key.key_id
        }
        assert verify_signed_json(
            device_keys,
            ALICE_ID,
            identity.self_signing_key.key_id,
            keys.public_key("self_signing"),
        )

        master_key = body[ALICE_ID][identity.master_key.public_key]
        assert master_key["keys"] == {
            identity.master_key.key_id: identity.master_key.public_key
        }
        assert verify_signed_json(
            master_key,
            ALICE_ID,
            f"ed25519:{ALICE_DEVICE_ID}",
            alice.olm.account.identity_keys["ed25519"],
        )

    async def test_sign_own_device_without_master_key(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse, usages=("self_signing",))
        self.mock_keys_query(aioresponse)
        await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        url = f"{BASE_URL_V3}/keys/signatures/upload"
        aioresponse.post(url, status=200, payload={})

        resp = await alice.sign_own_device()
        assert isinstance(resp, KeysSignaturesUploadResponse)

        # Without a trusted master key only the device is signed.
        (body,) = request_bodies(aioresponse, "POST", url)
        assert set(body[ALICE_ID]) == {ALICE_DEVICE_ID}

    async def test_sign_own_device_queries_identity(self, alice, aioresponse):
        alice.olm.cross_signing_private_keys = alice_private_keys()
        assert ALICE_ID not in alice.user_identities

        self.mock_keys_query(aioresponse)
        url = f"{BASE_URL_V3}/keys/signatures/upload"
        aioresponse.post(url, status=200, payload={})

        resp = await alice.sign_own_device()
        assert isinstance(resp, KeysSignaturesUploadResponse)
        assert ALICE_ID in alice.user_identities

    async def test_sign_own_device_errors(self, alice, aioresponse):
        with pytest.raises(LocalProtocolError, match="isn't known"):
            await alice.sign_own_device()

        alice.olm.cross_signing_private_keys = CrossSigningPrivateKeys(
            self_signing=seed("bob-self-signing")
        )
        self.mock_keys_query(aioresponse)
        with pytest.raises(LocalProtocolError, match="doesn't match the published"):
            await alice.sign_own_device()

        alice.olm.user_identities.clear()
        self.mock_keys_query(aioresponse, load_fixture("keys_query_bob_unsigned.json"))
        with pytest.raises(LocalProtocolError, match="has no cross-signing keys"):
            await alice.sign_own_device()

        self.mock_keys_query(
            aioresponse, status=500, payload={"errcode": "M_UNKNOWN", "error": "Err"}
        )
        resp = await alice.sign_own_device()
        assert isinstance(resp, KeysSignaturesUploadError)
        assert resp.status_code == "M_UNKNOWN"

    async def test_bootstrap_cross_signing(self, alice, aioresponse):
        url = f"{BASE_URL_V3}/keys/device_signing/upload"
        aioresponse.post(url, status=401, payload=load_fixture("uiaa_401.json"))
        aioresponse.post(url, status=200, payload={})

        resp = await alice.bootstrap_cross_signing()
        assert isinstance(resp, KeysDeviceSigningUploadAuthResponse)
        assert ALICE_ID not in alice.user_identities

        # The keys are only persisted once the server accepted them.
        keys = alice.olm.cross_signing_private_keys
        assert keys.master and keys.self_signing and keys.user_signing
        assert not alice.store.load_cross_signing_private_keys()

        auth = {"type": "m.login.password", "session": resp.session}
        resp = await alice.bootstrap_cross_signing(auth)
        assert isinstance(resp, KeysDeviceSigningUploadResponse)
        assert alice.store.load_cross_signing_private_keys() == keys

        # The same keys are uploaded again, with the auth dict.
        first, second = request_bodies(aioresponse, "POST", url)
        assert set(first) == {"master_key", "self_signing_key", "user_signing_key"}
        assert second == {**first, "auth": auth}
        assert alice.olm.cross_signing_private_keys == keys

        identity = alice.user_identities[ALICE_ID]
        assert identity == keys.as_identity(ALICE_ID)
        assert identity.master_key.as_dict() == first["master_key"]
        assert alice.store.load_user_identities()[ALICE_ID] == identity
        assert alice.is_user_verified(ALICE_ID)

        for usage in ("self_signing_key", "user_signing_key"):
            assert verify_signed_json(
                first[usage],
                ALICE_ID,
                identity.master_key.key_id,
                identity.master_key.public_key,
            )

        # Bootstrapping again reuses the stored keys.
        aioresponse.post(url, status=200, payload={})
        resp = await alice.bootstrap_cross_signing()
        assert isinstance(resp, KeysDeviceSigningUploadResponse)
        assert alice.olm.cross_signing_private_keys == keys

    async def test_bootstrap_cross_signing_error(self, alice, aioresponse):
        url = f"{BASE_URL_V3}/keys/device_signing/upload"
        aioresponse.post(
            url, status=403, payload={"errcode": "M_FORBIDDEN", "error": "No"}
        )

        resp = await alice.bootstrap_cross_signing()
        assert isinstance(resp, KeysDeviceSigningUploadError)
        assert ALICE_ID not in alice.user_identities
        assert not alice.store.load_cross_signing_private_keys()

    async def test_bootstrap_cross_signing_partial_keys(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse, usages=("self_signing",))
        self.mock_keys_query(aioresponse)
        keys = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        with pytest.raises(LocalProtocolError, match="Only some"):
            await alice.bootstrap_cross_signing()

        assert alice.olm.cross_signing_private_keys == keys
        assert alice.store.load_cross_signing_private_keys() == keys

    async def test_import_invalid_seed(self, alice, aioresponse):
        self.mock_secret_storage(aioresponse)
        encrypted = encrypt_secret(
            bytes(range(32)), "m.cross_signing.master", encode_base64(b"short").encode()
        )
        aioresponse.get(
            account_data_url("m.cross_signing.master"),
            status=200,
            payload={"encrypted": {KEY_ID: encrypted}},
        )

        with pytest.raises(ValueError, match="isn't 32 bytes"):
            await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        self.mock_secret_storage(aioresponse)
        aioresponse.get(
            account_data_url("m.cross_signing.master"),
            status=200,
            payload={"encrypted": "invalid"},
        )
        with pytest.raises(LocalProtocolError, match="isn't encrypted with the key"):
            await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

    async def test_verify_user(self, alice, aioresponse):
        # Bob's master key isn't signed by Alice yet.
        payload = load_fixture("keys_query_cross_signing.json")
        del payload["master_keys"][BOB_ID]["signatures"][ALICE_ID]
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(aioresponse, payload)
        keys = await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)
        assert alice.is_user_verified(ALICE_ID)
        assert not alice.is_user_verified(BOB_ID)

        url = f"{BASE_URL_V3}/keys/signatures/upload"
        aioresponse.post(url, status=200, payload={})

        resp = await alice.verify_user(BOB_ID)
        assert isinstance(resp, KeysSignaturesUploadResponse)
        assert alice.is_user_verified(BOB_ID)

        bob_master = alice.user_identities[BOB_ID].master_key
        user_signing_key = alice.user_identities[ALICE_ID].user_signing_key
        (body,) = request_bodies(aioresponse, "POST", url)
        signed = body[BOB_ID][bob_master.public_key]
        assert signed["keys"] == {bob_master.key_id: bob_master.public_key}
        assert set(signed["signatures"]) == {ALICE_ID}
        assert verify_signed_json(
            signed, ALICE_ID, user_signing_key.key_id, keys.public_key("user_signing")
        )
        # The signature matches the one in the original fixture.
        original = load_fixture("keys_query_cross_signing.json")
        assert (
            signed["signatures"][ALICE_ID]
            == original["master_keys"][BOB_ID]["signatures"][ALICE_ID]
        )

        # The signature is persisted.
        loaded = alice.store.load_user_identities()[BOB_ID]
        assert loaded.master_key.signatures[ALICE_ID] == signed["signatures"][ALICE_ID]

    async def test_verify_user_failure(self, alice, aioresponse):
        payload = load_fixture("keys_query_cross_signing.json")
        del payload["master_keys"][BOB_ID]["signatures"][ALICE_ID]
        self.mock_secret_storage(aioresponse)
        self.mock_secrets(aioresponse)
        self.mock_keys_query(aioresponse, payload)
        await alice.import_cross_signing_keys_from_recovery_key(RECOVERY_KEY)

        bob_master = alice.user_identities[BOB_ID].master_key
        failures = {BOB_ID: {bob_master.public_key: {"errcode": "M_INVALID_SIGNATURE"}}}
        aioresponse.post(
            f"{BASE_URL_V3}/keys/signatures/upload",
            status=200,
            payload={"failures": failures},
        )

        resp = await alice.verify_user(BOB_ID)
        assert isinstance(resp, KeysSignaturesUploadResponse)
        assert resp.failures == failures
        assert not alice.is_user_verified(BOB_ID)

    async def test_verify_user_errors(self, alice, aioresponse):
        with pytest.raises(LocalProtocolError, match="user-signing key isn't known"):
            await alice.verify_user(BOB_ID)

        alice.olm.cross_signing_private_keys = CrossSigningPrivateKeys(
            user_signing=seed("alice-user-signing")
        )
        with pytest.raises(LocalProtocolError, match="isn't trusted"):
            await alice.verify_user(BOB_ID)

        await self.import_keys(alice, aioresponse)
        alice.olm.cross_signing_private_keys.user_signing = seed("bob-master")
        with pytest.raises(LocalProtocolError, match="doesn't match the published"):
            await alice.verify_user(BOB_ID)

        alice.olm.cross_signing_private_keys = alice_private_keys()
        with pytest.raises(LocalProtocolError, match="aren't known"):
            await alice.verify_user("@carol:example.org")

        # A device id colliding with a cross-signing key id.
        bob_master = alice.user_identities[BOB_ID].master_key
        bob_device = alice.device_store[BOB_ID][BOB_DEVICE_ID]
        alice.device_store[BOB_ID][bob_master.public_key] = copy.copy(bob_device)
        alice.device_store[BOB_ID][
            bob_master.public_key
        ].device_id = bob_master.public_key
        with pytest.raises(LocalProtocolError, match="collides"):
            await alice.verify_user(BOB_ID)

    async def test_is_own_device_cross_signed(self, alice, aioresponse):
        await self.import_keys(alice, aioresponse)
        identity = alice.user_identities[ALICE_ID]

        # The fixture device carries a different key than our account.
        self.mock_keys_query(aioresponse)
        assert not await alice.is_own_device_cross_signed()

        payload = load_fixture("keys_query_cross_signing.json")
        device_keys = alice.olm.own_device_keys()
        payload["device_keys"][ALICE_ID][ALICE_DEVICE_ID] = device_keys
        self.mock_keys_query(aioresponse, copy.deepcopy(payload))
        assert not await alice.is_own_device_cross_signed()

        device_keys["signatures"][ALICE_ID][identity.self_signing_key.key_id] = (
            sign_json(seed("alice-self-signing"), device_keys)
        )
        self.mock_keys_query(aioresponse, payload)
        assert await alice.is_own_device_cross_signed()

        del payload["device_keys"][ALICE_ID]
        self.mock_keys_query(aioresponse, payload)
        assert not await alice.is_own_device_cross_signed()

        self.mock_keys_query(
            aioresponse, status=500, payload={"errcode": "M_UNKNOWN", "error": "Err"}
        )
        assert not await alice.is_own_device_cross_signed()

    async def test_encrypt_secret_roundtrip_with_client(self, alice, aioresponse):
        """A secret encrypted by nio can be fetched and decrypted by nio."""
        key = bytes(range(32))
        key_info = SecretStorageKeyInfo(KEY_ID, "m.secret_storage.v1.aes-hmac-sha2")
        encrypted = encrypt_secret(key, "m.example", b"secret")
        aioresponse.get(
            account_data_url("m.example"),
            status=200,
            payload={"encrypted": {KEY_ID: encrypted}},
        )
        assert await alice.get_secret("m.example", key, key_info) == b"secret"
