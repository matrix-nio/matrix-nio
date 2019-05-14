from helpers import ephemeral, ephemeral_dir, faker
from nio.crypto import (GroupSessionStore, InboundGroupSession, OlmAccount,
                        OutboundGroupSession, OutboundSession, SessionStore)
from nio.exceptions import OlmTrustError
from nio.store import Ed25519Key, Key, KeyStore, MatrixStore

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"
TEST_ROOM = "!test:example.org"

class TestClass(object):
    def test_session_store(self):
        account = OlmAccount()
        store = SessionStore()
        session = OutboundSession(account, BOB_CURVE, BOB_ONETIME)

        assert session not in store
        assert len(store.values()) == 0
        assert not store.get(BOB_CURVE)

        assert store.add(BOB_CURVE, session)

        assert len(store.values()) == 1
        assert session in store

        assert not store.add(BOB_CURVE, session)

        assert len(store.values()) == 1
        assert session in store

        assert (BOB_CURVE, [session]) == list(store.items())[0]

    def test_group_session_store(self):
        store = GroupSessionStore()
        account = OlmAccount()

        out_group = OutboundGroupSession()
        session = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            BOB_CURVE,
            TEST_ROOM
        )

        assert session not in store
        assert not store.get(TEST_ROOM, BOB_CURVE, session.id)

        assert store.add(session)

        assert store.get(TEST_ROOM, BOB_CURVE, session.id)
        assert session in store

        assert not store.add(session)

        assert store[TEST_ROOM] == {BOB_CURVE: {session.id: session}}
