import pytest

from nio import EncryptionError
from nio.crypto import (InboundGroupSession, OlmAccount, OutboundGroupSession,
                        OutboundSession, Session)

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"
TEST_ROOM = "!test:example.org"

class TestClass(object):
    def test_account(self):
        account = OlmAccount()

        assert (account.identity_keys ==
                OlmAccount.from_pickle(account.pickle()).identity_keys)

    def test_session(self):
        account = OlmAccount()
        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)

        assert session.id == Session.from_pickle(
            session.pickle(),
            session.creation_time
        ).id
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
