from helpers import faker

from nio.crypto import (
    DeviceStore,
    GroupSessionStore,
    InboundGroupSession,
    OlmAccount,
    OutboundGroupSession,
    OutboundSession,
    SessionStore,
)

BOB_ID = "@bob:example.org"
BOB_DEVICE = "AGMTSWVYML"
BOB_CURVE = "T9tOKF+TShsn6mk1zisW2IBsBbTtzDNvw99RBFMJOgI"
BOB_ONETIME = "6QlQw3mGUveS735k/JDaviuoaih5eEi6S1J65iHjfgU"
TEST_ROOM = "!test:example.org"


class TestClass:
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

    def test_session_store_order(self):
        alice = OlmAccount()
        bob = OlmAccount()
        bob_curve = bob.identity_keys["curve25519"]
        bob.generate_one_time_keys(2)

        store = SessionStore()

        first, second = bob.one_time_keys["curve25519"].values()

        session2 = OutboundSession(alice, bob_curve, second)
        session = OutboundSession(alice, bob_curve, first)

        assert session.id != session2.id

        assert session not in store

        assert store.add(bob_curve, session)
        assert len(store[bob_curve]) == 1
        assert session in store
        assert store.add(bob_curve, session2) is True
        print(store.values())
        assert len(store[bob_curve]) == 2

        session_a, session_b = store[bob_curve]

        assert session_a.use_time > session_b.use_time

    def test_device_get_by_sender_key(self):
        store = DeviceStore()

        for _ in range(10):
            store.add(faker.olm_device())

        device = faker.olm_device()

        store.add(device)

        fetched_device = store.device_from_sender_key(device.user_id, device.curve25519)

        assert fetched_device == device

    def test_group_session_store(self):
        store = GroupSessionStore()
        account = OlmAccount()

        out_group = OutboundGroupSession()
        session = InboundGroupSession(
            out_group.session_key,
            account.identity_keys["ed25519"],
            BOB_CURVE,
            TEST_ROOM,
        )

        assert session not in store
        assert not store.get(TEST_ROOM, BOB_CURVE, session.id)

        assert store.add(session)

        assert store.get(TEST_ROOM, BOB_CURVE, session.id)
        assert session in store

        assert not store.add(session)

        assert store[TEST_ROOM] == {BOB_CURVE: {session.id: session}}
