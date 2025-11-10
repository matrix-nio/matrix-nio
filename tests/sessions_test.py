import pytest

from nio import EncryptionError
from nio.crypto import (
    InboundSession,
    OlmAccount,
    OutboundGroupSession,
    OutboundSession,
    Session,
)

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

        inbound = InboundSession(bob, message, alice.identity_keys['curve25519'])
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

    def test_outbound_group_session_pickle(self):
        session = OutboundGroupSession()

        assert (
            session.id
            == OutboundGroupSession.from_pickle(session.pickle()).id
        )
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
