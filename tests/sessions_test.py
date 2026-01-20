import pytest
from unpaddedbase64 import encode_base64

from nio import EncryptionError
from nio._compat import package_installed
from nio.crypto import (
    InboundGroupSession,
    InboundSession,
    OlmAccount,
    OutboundGroupSession,
    OutboundSession,
    Session,
)

if package_installed("olm"):
    import olm
    from vodozemac import PreKeyMessage

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"
TEST_ROOM = "!test:example.org"


class TestClass:
    def test_account_pickle(self):
        account = OlmAccount()

        assert (
            account.identity_keys
            == OlmAccount.from_pickle(account.pickle()).identity_keys
        )

    def test_outbound_session_pickle(self):
        account = OlmAccount()
        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)

        assert (
            session.id
            == Session.from_pickle(session.pickle(), session.creation_time).id
        )
        assert not session.expired

    def test_olm_session_encryption(self):
        alice = OlmAccount()
        bob = OlmAccount()
        plaintext = "It's a secret to everybody"
        bob_curve = bob.identity_keys["curve25519"]

        bob.generate_one_time_keys(1)
        bob_onetime = list(bob.one_time_keys["curve25519"].values())[0]

        session = OutboundSession(alice, bob_curve, bob_onetime)
        creation_time = session.use_time

        # Encrypt a message and check that the use time increased.
        message = session.encrypt(plaintext)
        assert session.use_time >= creation_time

        inbound = InboundSession(bob, message, alice.identity_keys["curve25519"])
        creation_time = inbound.use_time

        # Decrypt a message and check that the use time increased.
        decrypted_plaintext = inbound.decrypt(message)
        assert inbound.use_time >= creation_time

        assert decrypted_plaintext == plaintext

        # Encrypt/Decrypt another message.
        plaintext2 = "It's still a secret to everybody"
        message2 = session.encrypt(plaintext2)
        assert session.use_time >= creation_time
        decrypted_plaintext2 = inbound.decrypt(message2)
        assert inbound.use_time >= creation_time
        assert decrypted_plaintext2 == plaintext2

        pickle = inbound.pickle("")

        unpickled = Session.from_pickle(
            pickle, inbound.creation_time, "", inbound.use_time
        )

        use_time = unpickled.use_time
        message = unpickled.encrypt(plaintext)

        assert unpickled.use_time > use_time

        pickle = session.pickle("")
        unpickled = Session.from_pickle(
            pickle, session.creation_time, "", session.use_time
        )
        use_time = unpickled.use_time
        decrypted_plaintext = unpickled.decrypt(message)
        assert unpickled.use_time >= use_time
        assert decrypted_plaintext == plaintext

    @pytest.mark.skipif(not package_installed("olm"), reason="requires olm")
    def test_libolm_compatible_session_encryption(self):
        vodozemac = OlmAccount()
        vodozemac_curve = vodozemac.identity_keys["curve25519"]
        vodozemac.generate_one_time_keys(1)

        libolm = olm.Account()
        libolm_curve = libolm.identity_keys["curve25519"]
        libolm.generate_one_time_keys(1)

        vodozemac_onetime = list(vodozemac.one_time_keys["curve25519"].values())[0]
        libolm_onetime = list(libolm.one_time_keys["curve25519"].values())[0]

        plaintext = "It's a secret to everybody"

        # Encrypt a message with vodozemac, decrypt it with libolm
        session = OutboundSession(vodozemac, libolm_curve, libolm_onetime)
        message = session.encrypt(plaintext)

        ciphertext = encode_base64(message.to_parts()[1])

        message = olm.OlmPreKeyMessage(ciphertext)
        inbound = olm.InboundSession(libolm, message, vodozemac_curve)
        decrypted_message = inbound.decrypt(message)
        assert decrypted_message == plaintext

        # Encrypt a message with libolm, decrypt it with vodozemac
        session = olm.OutboundSession(libolm, vodozemac_curve, vodozemac_onetime)
        message = session.encrypt(plaintext)

        ciphertext = message.ciphertext

        message = PreKeyMessage.from_base64(ciphertext)
        inbound = InboundSession(vodozemac, message, libolm_curve)
        decrypted_message = inbound.decrypt(message)
        assert decrypted_message == plaintext

    def test_outbound_group_session_pickle(self):
        session = OutboundGroupSession()

        assert session.id == OutboundGroupSession.from_pickle(session.pickle()).id
        assert not session.expired

    def test_outbound_group_session(self):
        session = OutboundGroupSession()
        assert not session.expired
        assert not session.shared
        assert session.message_count == 0

        with pytest.raises(EncryptionError):
            session.encrypt("Hello")

        session.mark_as_shared()
        assert session.shared

        session.encrypt("Hello")
        assert session.message_count == 1

        session.message_count = 101

        assert session.expired

        with pytest.raises(EncryptionError):
            session.encrypt("Hello")

    @pytest.mark.skipif(not package_installed("olm"), reason="requires olm")
    def test_libolm_compatible_group_session_encryption(self):
        plaintext = "It's a secret to everybody"

        # Encrypt a message with vodozemac, decrypt it with libolm
        vodozemac = OutboundGroupSession()
        vodozemac.shared = True
        libolm = olm.InboundGroupSession(vodozemac.session_key)

        ciphertext = vodozemac.encrypt(plaintext)

        decrypted_message = libolm.decrypt(ciphertext)[0]
        assert decrypted_message == plaintext

        # Encrypt a message with libolm, decrypt it with vodozemac
        libolm = olm.OutboundGroupSession()
        vodozemac = InboundGroupSession(libolm.session_key, "", "", "")

        ciphertext = libolm.encrypt(plaintext)

        decrypted_message = vodozemac.decrypt(ciphertext)[0]
        assert decrypted_message == plaintext
