import pytest

from nio.crypto import Sas, SasState
from nio.exceptions import LocalProtocolError
from nio.events import (
    KeyVerificationStart,
    KeyVerificationAccept,
    KeyVerificationKey
)
from helpers import faker

alice_id = faker.mx_id()
alicd_device = faker.device_id()
alice_keys = faker.olm_key_pair()

bob_id = faker.mx_id()
bob_device = faker.device_id()
bob_keys = faker.olm_key_pair()


class TestClass(object):
    def test_sas_creation(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
        )

        with pytest.raises(LocalProtocolError):
            alice.accept_verification()

    def test_sas_start(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
        )
        assert alice.state == SasState.created

        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }

        start_event = KeyVerificationStart.from_dict(start)
        assert isinstance(start_event, KeyVerificationStart)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device,
            bob_keys["ed25519"],
            start_event
        )

        assert bob.state == SasState.started

    def test_sas_accept(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device,
            bob_keys["ed25519"],
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification()
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        assert isinstance(accept_event, KeyVerificationAccept)
        alice.receive_accept_event(accept_event)
        assert alice.state == SasState.accepted

    def test_sas_share_keys(self):
        alice = Sas(
            alice_id,
            alicd_device,
            alice_keys["ed25519"],
            bob_id,
            bob_device
        )
        start = {
            "sender": alice_id,
            "content": alice.start_verification()
        }
        start_event = KeyVerificationStart.from_dict(start)

        bob = Sas.from_key_verification_start(
            bob_id,
            bob_device,
            bob_keys["ed25519"],
            start_event
        )

        accept = {
            "sender": bob_id,
            "content": bob.accept_verification()
        }
        accept_event = KeyVerificationAccept.from_dict(accept)
        alice.receive_accept_event(accept_event)

        alice_key = {
            "sender": alice_id,
            "content": alice.share_key()
        }

        key_event = KeyVerificationKey.from_dict(alice_key)
        assert isinstance(key_event, KeyVerificationKey)
        bob.receive_key_event(key_event)
        assert bob.state == SasState.key_received

        bob_key = {
            "sender": bob_id,
            "content": bob.share_key()
        }

        key_event = KeyVerificationKey.from_dict(bob_key)
        assert isinstance(key_event, KeyVerificationKey)
        alice.receive_key_event(key_event)
        assert alice.state == SasState.key_received
        assert alice.get_emoji() == bob.get_emoji()
