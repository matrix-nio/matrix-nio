Cross-signing and Secret Storage
================================

nio implements the `cross-signing`_ and `Secret Storage`_ (SSSS) modules of
the Matrix client-server API (v1.19). Cross-signing lets a user vouch for
their own devices and for other users with a small set of signing keys, so
every device doesn't have to be verified individually:

- the **master key** is the root of a user's identity,
- the **self-signing key**, signed by the master key, signs the user's own
  devices,
- the **user-signing key**, signed by the master key, signs the master keys of
  other users the user has verified.

The private halves of these keys are usually stored in Secret Storage, a set
of account data events encrypted with a key that the user holds as a
*recovery key* (a base58 string) or derives from a *passphrase*.

What nio does
-------------

- The cross-signing keys of every user in a ``/keys/query`` response are
  parsed, checked along the master → self-signing chain and stored as
  :class:`nio.crypto.UserIdentity` objects, available through
  ``client.user_identities``.
- A device that carries a valid signature by its owner's self-signing key is
  flagged as ``OlmDevice.cross_signed``.
- ``client.is_user_verified(user_id)`` tells if a user's identity is trusted:
  our own identity is trusted once we hold the private master key that
  matches the published one, another user is trusted if their master key is
  signed by our user-signing key.
- The private keys of our own user can be imported from Secret Storage with a
  recovery key or passphrase, or freshly created and uploaded.
- Our own device can be cross-signed and other users can be verified.
- A changed master key is reported in ``KeysQueryResponse.changed_identities``
  and voids the trust in that user; outbound room sessions shared with the
  user are invalidated. If our own master key changed, e.g. because the keys
  were reset in another client, the stored private keys are discarded.

The existing manual trust model, ``verify_device()`` and
:class:`nio.crypto.TrustState`, stays untouched: cross-signing adds
information, it doesn't decide on its own which devices receive room keys. A
device can be considered trusted if its user is verified and the device is
cross-signed::

    device = client.device_store[user_id][device_id]
    if client.is_user_verified(user_id) and device.cross_signed:
        client.verify_device(device)

Importing the keys from Secret Storage
--------------------------------------

This is the common case for a new device of a user whose cross-signing keys
were set up by another client, e.g. Element. The account's default secret
storage key is checked against the recovery key, the private cross-signing
keys are decrypted, compared with the published keys and stored, encrypted
with the ``pickle_key``, in the encryption store::

    from nio import AsyncClient, ErrorResponse

    client = AsyncClient("https://example.org", "@alice:example.org")
    await client.login("hunter1")

    keys = await client.import_cross_signing_keys_from_recovery_key(
        "EsTj 3yST y93F SLpB jJsz eAXc 2XzA ygD3 w69H fGaN TKBj jXEd"
    )
    # or: await client.import_cross_signing_keys_from_passphrase("...")

    if isinstance(keys, ErrorResponse):
        print(f"Import failed: {keys}")
    else:
        resp = await client.sign_own_device()
        print(await client.is_own_device_cross_signed())

A malformed or wrong recovery key raises ``ValueError``, an account without
Secret Storage or cross-signing raises ``LocalProtocolError``.

``sign_own_device()`` signs this device's keys with the self-signing key and
uploads the signature, afterwards other clients of the user treat this device
as verified. If the private master key is known, the master key is
additionally signed with the device key, as recommended by the spec.

Creating new cross-signing keys
-------------------------------

An account without cross-signing keys, e.g. a bot, can create and upload a
set of keys itself. Replacing existing keys requires user-interactive
authentication::

    from nio import KeysDeviceSigningUploadAuthResponse

    resp = await client.bootstrap_cross_signing()

    if isinstance(resp, KeysDeviceSigningUploadAuthResponse):
        auth = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "@alice:example.org"},
            "password": "hunter1",
            "session": resp.session,
        }
        resp = await client.bootstrap_cross_signing(auth)

    await client.sign_own_device()

The keys are kept in the encryption store only, they are not written to
Secret Storage. Other clients of the user can therefore not import them;
writing to Secret Storage is a possible follow-up.

Verifying other users
---------------------

After a user's identity was verified out of band, for example by comparing
the master key fingerprint (``client.user_identities[user_id].master_key
.public_key``), the user's master key can be signed with our user-signing
key::

    resp = await client.verify_user("@bob:example.org")
    assert client.is_user_verified("@bob:example.org")

The signature is uploaded and stored, ``is_user_verified()`` returns True
from then on, also for later sessions.

Lower-level building blocks
---------------------------

- ``client.get_secret_storage_default_key()`` and ``client.get_secret()``
  fetch and decrypt arbitrary secrets from Secret Storage.
- ``client.keys_device_signing_upload()`` and
  ``client.keys_signatures_upload()`` wrap the two cross-signing endpoints.
- :mod:`nio.crypto.ssss` holds the pure cryptographic functions: recovery
  key encoding, passphrase key derivation and secret encryption.
- :class:`nio.crypto.CrossSigningPrivateKeys` signs JSON objects with the
  private keys, :class:`nio.crypto.CrossSigningKey` represents the published
  public keys.

Not implemented
---------------

- Writing secrets to Secret Storage.
- Secret sharing between devices (``m.secret.request`` / ``m.secret.send``).
- Verifying other users' devices interactively with cross-signing (the SAS
  verification in nio only marks devices as verified locally).
- Server-side key backup.

.. _cross-signing: https://spec.matrix.org/v1.19/client-server-api/#cross-signing
.. _Secret Storage: https://spec.matrix.org/v1.19/client-server-api/#secret-storage
